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
SYSTEMCTL = "/usr/bin/systemctl"
UNIT_NAME = os.path.basename(UNIT)
# systemd.unit(5) system-manager unit load path. The running manager's own
# UnitPath is scanned as well, so neither list can narrow the other.
LOAD_PATHS = ("/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
              "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
              "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
              "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late")
# Names whose ".d" drop-ins and dependency directories apply to the unit: its
# own name, its dash-truncated prefixes and the type-wide "service" scope.
UNIT_SCOPES = (UNIT_NAME, "swarma-slotd-.service", "swarma-.service", "service")
DEPENDENCY_DIRS = (".wants", ".requires", ".upholds")
# Effective state systemd must report for the unit after daemon-reload.
LOADED_UNIT = {"LoadState": "loaded", "FragmentPath": UNIT, "DropInPaths": "", "SourcePath": "",
               "Names": UNIT_NAME, "UnitFileState": "disabled", "NeedDaemonReload": "no"}


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


IDENTITY = ("st_dev", "st_ino", "st_uid", "st_gid", "st_nlink", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")


def same_identity(a, b):
    return all(getattr(a, k) == getattr(b, k) for k in IDENTITY)


def open_file(path, limit, mode=None):
    """Return a held descriptor, its bytes and their identity snapshot."""
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
        if len(data) > limit or not same_identity(before, os.fstat(fd)):
            raise Refusal("file too large or changed")
        return fd, bytes(data), before
    except BaseException:
        os.close(fd)
        raise


def read_file(path, limit, mode=None, identity=False):
    fd, data, snapshot = open_file(path, limit, mode)
    os.close(fd)
    return (data, snapshot) if identity else data


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


def command(args, pass_fds=()):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds,
                            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, cwd="/", timeout=30)
    if result.returncode:
        # Do not copy tool/policy output into the installer report.
        raise Refusal("prerequisite or systemd command refused")
    return result.stdout


def unit_link(fd, name):
    """True for an alias symlink to the unit, or a dependency directory
    (enablement or reverse dependency) that links the unit."""
    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            return os.path.basename(os.readlink(name, dir_fd=fd)) == UNIT_NAME
        if not stat.S_ISDIR(st.st_mode) or not name.endswith(DEPENDENCY_DIRS):
            return False
        sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return False  # Removed since listing; a removed entry cannot apply.
    try:
        return UNIT_NAME in os.listdir(sub)
    finally:
        os.close(sub)


def unit_namespace(paths):
    """Refuse every load-path entry that would add, replace, alias, extend or
    pull in the unit; the planned fragment path itself is checked by its plan."""
    names = {scope + suffix for scope in UNIT_SCOPES for suffix in (".d",) + DEPENDENCY_DIRS}
    for path in paths:
        try:
            fd = directory(path)
        except FileNotFoundError:
            continue
        try:
            for name in os.listdir(fd):
                if os.path.join(path, name) == UNIT:
                    continue
                if name == UNIT_NAME or name.startswith(UNIT_NAME + ".") or name in names or unit_link(fd, name):
                    raise Refusal("additional or overridden daemon unit refused")
        finally:
            os.close(fd)


def manager_unit_paths():
    try:
        paths = command([SYSTEMCTL, "--system", "--no-ask-password", "show", "--property=UnitPath", "--value"]).decode("ascii").split()
    except UnicodeDecodeError:
        paths = []
    if not paths or any(not p.startswith("/") or os.path.normpath(p) != p for p in paths):
        raise Refusal("systemd unit path unavailable")
    return paths


def loaded_unit():
    """Read back what systemd actually loaded after daemon-reload."""
    keys = sorted(LOADED_UNIT) + ["ActiveState"]
    out = command([SYSTEMCTL, "--system", "--no-ask-password", "show", "--property=" + ",".join(keys), "--", UNIT_NAME])
    props = {}
    try:
        lines = out.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        lines = []
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key in keys and key not in props:
            props[key] = value
    if sorted(props) != sorted(keys) or any(props[k] != v for k, v in LOADED_UNIT.items()) or props["ActiveState"] not in ("inactive", "failed"):
        raise Refusal("loaded daemon unit differs from the reviewed package; not started or enabled")


def config_inventory(fd):
    """The installer-owned config directory may hold only the policy file."""
    if any(name != os.path.basename(POLICY) for name in os.listdir(fd)):
        raise Refusal("unexpected entry in config directory refused")


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
    held, binary, binary_id = open_file(args.binary, MAX_BINARY)
    try:
        if len(args.sha256) != 64 or hashlib.sha256(binary).hexdigest() != args.sha256:
            raise Refusal("binary digest mismatch")
        if not binary_id.st_mode & 0o111:
            raise Refusal("binary not executable")
        policy, policy_id = read_file(args.policy, 65536, 0o640, identity=True)
        unit = read_file(os.path.join(package, "swarma-slotd-demo.service"), 16384, 0o644)
        stop = read_file(os.path.join(package, "stop.sh"), 4096, 0o755)
        unit_namespace(LOAD_PATHS)
        for path in ("/usr/libexec", "/usr/local/sbin", "/etc/systemd/system", "/etc"):
            os.close(directory(path))
        config = os.path.dirname(POLICY)
        create_config = not os.path.lexists(config)
        if not create_config:
            # The installer owns this directory; an existing one must already match
            # what it would create: exact mode, no special bits, only the policy.
            fd = directory(config)
            try:
                if stat.S_IMODE(os.fstat(fd).st_mode) != 0o755:
                    raise Refusal("config directory mode mismatch")
                config_inventory(fd)
            finally:
                os.close(fd)
        plans = [planned_file(BINARY, binary, 0o755), planned_file(UNIT, unit, 0o644),
                 planned_file(STOP, stop, 0o755), planned_file(POLICY, policy, 0o640)]
        unit_namespace([path for path in manager_unit_paths() if path not in LOAD_PATHS])
        # Reuse the daemon's exact policy parser and protected-input checks. This
        # mode does not open state, bind a socket, allocate accounts or load BPF.
        # It executes the held, hashed inode; neither it nor the policy may change.
        command(["/proc/self/fd/%d" % held, "--install-check", args.policy, args.manager_group], pass_fds=(held,))
        again, again_id = read_file(args.policy, 65536, 0o640, identity=True)
        if not same_identity(binary_id, os.fstat(held)) or again != policy or not same_identity(policy_id, again_id):
            raise Refusal("input changed during prerequisite check")
    finally:
        os.close(held)
    if args.check:
        print("slotd install plan: ok; no files published, daemon not started; station qualification still required")
        return
    state = command([SYSTEMCTL, "--system", "--no-ask-password", "show", "--property=ActiveState", "--value", "--", UNIT_NAME]).strip()
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
    command([SYSTEMCTL, "--system", "--no-ask-password", "daemon-reload"])
    loaded_unit()
    print("slotd installed; daemon not started or enabled by installer; start only after station qualification")


if __name__ == "__main__":
    try:
        main()
    except (Refusal, OSError, subprocess.SubprocessError) as exc:
        # Deliberately omit input path/content and subprocess output.
        print("slotd install refused: " + (str(exc) if isinstance(exc, Refusal) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
