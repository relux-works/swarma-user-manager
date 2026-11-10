#!/usr/bin/python3
"""First-install publisher. --check performs the same reads and no publication."""
import argparse
import hashlib
import os
import secrets
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
MAX_BINARY = 64 * 1024 * 1024
POLICY = "/etc/swarma-slotd-demo/policy.json"
UNIT = "/etc/systemd/system/swarma-slotd-demo.service"
BINARY = "/usr/libexec/swarma-slotd-demo"
STOP = "/usr/local/sbin/swarma-slotd-demo-stop"


class Refusal(Exception):
    pass


def no_acl(fd):
    if any(name.startswith("system.posix_acl_") for name in os.listxattr(fd)):
        raise Refusal("ACL-bearing object refused")


def directory(path):
    if not path.startswith("/") or os.path.normpath(path) != path:
        raise Refusal("absolute normalized path required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in [""] + path.strip("/").split("/"):
            if part:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = nxt
            st = os.fstat(fd)
            if st.st_uid != 0 or st.st_gid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
                raise Refusal("unprotected ancestor refused")
            no_acl(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(path, limit, mode=None):
    parent = directory(os.path.dirname(path))
    try:
        fd = os.open(os.path.basename(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022:
            raise Refusal("unprotected file refused")
        if mode is not None and stat.S_IMODE(before.st_mode) != mode:
            raise Refusal("file mode mismatch")
        no_acl(fd)
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_nlink", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(data) > limit or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise Refusal("file too large or changed")
        return bytes(data)
    finally:
        os.close(fd)


def planned_file(path, data, mode):
    try:
        current = read_file(path, MAX_BINARY, mode)
    except FileNotFoundError:
        return (path, data, mode, True)
    if current != data:
        raise Refusal("existing installation differs; reviewed offline upgrade required")
    return (path, data, mode, False)


def publish_file(path, data, mode):
    """Exclusive publication never replaces an existing inode, even after plan."""
    parent = directory(os.path.dirname(path))
    name = os.path.basename(path)
    temp = ".slotd-install-" + secrets.token_hex(16)
    fd = -1
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        os.link(temp, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.unlink(temp, dir_fd=parent)
        os.fsync(parent)
    finally:
        if fd >= 0:
            os.close(fd)
            try:
                os.unlink(temp, dir_fd=parent)
            except FileNotFoundError:
                pass
        os.close(parent)


def command(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, cwd="/", timeout=30)
    if result.returncode:
        # Do not copy tool/policy output into the installer report.
        raise Refusal("prerequisite or systemd command refused")
    return result.stdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate and plan only; no host writes")
    parser.add_argument("--binary", required=True, help="protected reviewed Linux binary")
    parser.add_argument("--sha256", required=True, help="independently verified binary digest")
    parser.add_argument("--policy", required=True, help="protected root:root 0640 operator policy")
    parser.add_argument("--manager-group", required=True, help="existing caller's non-root primary group")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise Refusal("root on Linux required")
    os.umask(0o077)
    package = os.path.dirname(os.path.abspath(__file__))
    binary = read_file(args.binary, MAX_BINARY)
    if len(args.sha256) != 64 or hashlib.sha256(binary).hexdigest() != args.sha256:
        raise Refusal("binary digest mismatch")
    if not os.stat(args.binary, follow_symlinks=False).st_mode & 0o111:
        raise Refusal("binary not executable")
    policy = read_file(args.policy, 65536, 0o640)
    unit = read_file(os.path.join(package, "swarma-slotd-demo.service"), 16384, 0o644)
    stop = read_file(os.path.join(package, "stop.sh"), 4096, 0o755)
    # Reuse the daemon's exact policy parser and protected-input checks. This
    # mode does not open state, bind a socket, allocate accounts or load BPF.
    command([args.binary, "--install-check", args.policy, args.manager_group])
    for other in ("/run/systemd/system/swarma-slotd-demo.service", "/usr/lib/systemd/system/swarma-slotd-demo.service",
                  UNIT + ".d", "/run/systemd/system/swarma-slotd-demo.service.d", "/usr/lib/systemd/system/swarma-slotd-demo.service.d"):
        if os.path.lexists(other):
            raise Refusal("additional or overridden daemon unit refused")
    for path in ("/usr/libexec", "/usr/local/sbin", "/etc/systemd/system", "/etc"):
        os.close(directory(path))
    config = os.path.dirname(POLICY)
    create_config = not os.path.lexists(config)
    if not create_config:
        os.close(directory(config))
    plans = [planned_file(BINARY, binary, 0o755), planned_file(UNIT, unit, 0o644),
             planned_file(STOP, stop, 0o755), planned_file(POLICY, policy, 0o640)]
    if args.check:
        print("slotd install plan: ok; no files published, daemon not started; station qualification still required")
        return
    state = command(["/usr/bin/systemctl", "--system", "--no-ask-password", "show", "--property=ActiveState", "--value", "--", "swarma-slotd-demo.service"]).strip()
    if state not in (b"inactive", b"failed"):
        raise Refusal("daemon must be stopped before installation")
    if create_config:
        parent = directory("/etc")
        try:
            os.mkdir("swarma-slotd-demo", 0o755, dir_fd=parent)
            os.chmod("swarma-slotd-demo", 0o755, dir_fd=parent, follow_symlinks=False)
            os.fsync(parent)
        finally:
            os.close(parent)
    for path, data, mode, missing in plans:
        if missing:
            publish_file(path, data, mode)
    command(["/usr/bin/systemctl", "--system", "--no-ask-password", "daemon-reload"])
    print("slotd installed; daemon not started or enabled by installer; start only after station qualification")


if __name__ == "__main__":
    try:
        main()
    except (Refusal, OSError, subprocess.SubprocessError) as exc:
        # Deliberately omit input path/content and subprocess output.
        print("slotd install refused: " + (str(exc) if isinstance(exc, Refusal) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
