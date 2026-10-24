#!/bin/sh
# PROPOSED ONLY: owner-reviewed disposable Linux qualification, never installation.
# No sudoers changes. Before any future drop-in, use the host sudo-rs visudo -cf.
set -eu
exec /usr/bin/python3 - "$@" <<'PY'
import hashlib, json, os, re, stat, subprocess, sys

BASE = '/var/lib/swarma-linuxos-qualification'
POLICY = '/etc/swarma-linuxos-qualification.json'
MARKER = b'linuxos-disposable-qualification/1\n'
ALLOWED = {'marker', 'policy.json', 'candidate.test', 'candidate.sha256', 'state.json'}

def require(value, reason):
    if not value:
        raise RuntimeError(reason)

def xattrs(fd):
    for key in ('system.posix_acl_access', 'system.posix_acl_default', 'security.capability'):
        require(key not in os.listxattr(fd), 'unexpected ACL/capability')

def walk(path, protected):
    require(path.startswith('/') and os.path.normpath(path) == path, 'absolute clean path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.split('/')[1:]:
            require(part not in ('', '.', '..'), 'invalid component')
            if protected:
                s = os.fstat(fd)
                require(s.st_uid == 0 and s.st_gid == 0 and s.st_mode & 0o022 == 0, 'unsafe parent')
                xattrs(fd)
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = new
        if protected:
            s = os.fstat(fd)
            require(s.st_uid == 0 and s.st_gid == 0 and s.st_mode & 0o022 == 0, 'unsafe directory')
            xattrs(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise

def read_at(parent, name, mode=None, maximum=256*1024*1024):
    probe = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(probe)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, 'unsafe input file')
    finally:
        os.close(probe)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        s = os.fstat(fd)
        require((s.st_dev, s.st_ino, s.st_mode) == (before.st_dev, before.st_ino, before.st_mode), 'input changed')
        if mode is not None:
            require(s.st_uid == 0 and s.st_gid == 0 and stat.S_IMODE(s.st_mode) == mode, 'unsafe protected file')
            xattrs(fd)
        out = bytearray()
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - len(out)))
            if not chunk:
                break
            out.extend(chunk)
            require(len(out) <= maximum, 'input exceeds bound')
        return bytes(out)
    finally:
        os.close(fd)

def write_at(parent, name, data, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        xattrs(fd)
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            require(n > 0, 'short write')
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)

def validated(parent):
    require(read_at(parent, 'marker', 0o600, 1024) == MARKER, 'marker mismatch')
    expected = read_at(parent, 'candidate.sha256', 0o600, 65).decode().strip()
    require(re.fullmatch('[0-9a-f]{64}', expected), 'invalid pinned SHA')
    require(hashlib.sha256(read_at(parent, 'candidate.test', 0o500)).hexdigest() == expected, 'candidate SHA mismatch')
    read_at(parent, 'policy.json', 0o600, 1024*1024)

def run(mode):
    # Root-owned path, approved exact bytes. No shell or inherited environment.
    code = subprocess.run([BASE + '/candidate.test', '-test.run=^TestRootQualification$',
                           '-test.v', '-test.timeout=35s'],
                          env={'LINUXOS_ROOT_QUALIFICATION': mode, 'PATH': '/usr/bin:/bin'}, cwd='/').returncode
    require(code == 0, 'qualification ' + mode + ' failed with exit ' + str(code) + '; preserve fixture for guarded recovery')

try:
    require(os.geteuid() == 0, 'root required; proposed script was not executed')
    require(len(sys.argv) >= 2 and sys.argv[1] in ('apply', 'verify', 'rollback'),
            'usage: root-qualification.sh apply ABS_TEST_BINARY APPROVED_SHA | verify | rollback')
    mode = sys.argv[1]
    require(len(sys.argv) == (4 if mode == 'apply' else 2), 'invalid arguments')
    parent = walk('/var/lib', True)
    try:
        if mode == 'apply':
            source, expected = sys.argv[2:]
            require(re.fullmatch('[0-9a-f]{64}', expected), 'owner-approved SHA required')
            source_parent = walk(os.path.dirname(source), False)
            try:
                candidate = read_at(source_parent, os.path.basename(source))
            finally:
                os.close(source_parent)
            require(hashlib.sha256(candidate).hexdigest() == expected, 'source SHA mismatch')
            etc = walk('/etc', True)
            try:
                policy = read_at(etc, os.path.basename(POLICY), 0o600, 1024*1024)
            finally:
                os.close(etc)
            p = json.loads(policy)
            require(isinstance(p, dict) and set(p) == {'Min', 'Max', 'ReservedUIDs', 'ReservedGIDs'}, 'policy fields required')
            require(type(p['Min']) is int and type(p['Max']) is int and 0 < p['Min'] <= p['Max'] <= 2**32-2
                    and p['Max']-p['Min'] <= 1000000, 'invalid reviewed range')
            for key in ('ReservedUIDs', 'ReservedGIDs'):
                require(isinstance(p[key], list) and all(type(n) is int and 0 <= n <= 2**32-1 for n in p[key]), 'invalid journal reservations')
            # Owner supplies an unused test range and all actual journal holds.
            # mkdir is exclusive: never adopt or erase an existing fixture.
            os.mkdir(os.path.basename(BASE), 0o700, dir_fd=parent)
            os.fsync(parent)
            d = walk(BASE, True)
            try:
                write_at(d, 'marker', MARKER, 0o600)
                write_at(d, 'policy.json', policy, 0o600)
                write_at(d, 'candidate.test', candidate, 0o500)
                write_at(d, 'candidate.sha256', (expected+'\n').encode(), 0o600)
                os.fchmod(d, 0o711)
                os.fsync(d)
                validated(d)
                run('apply')
                run('verify')
                require(set(os.listdir(d)) == ALLOWED, 'unexpected residue; owner recovery required')
            finally:
                os.close(d)
        else:
            d = walk(BASE, True)
            try:
                validated(d)
                if mode == 'rollback':
                    run('rollback')
                run('verify')
                require(set(os.listdir(d)) == ALLOWED, 'unexpected residue; owner recovery required')
                if mode == 'rollback':
                    # Only verified known regular files. No recursive discard.
                    for name in sorted(ALLOWED):
                        read_at(d, name, 0o500 if name == 'candidate.test' else 0o600)
                    for name in sorted(ALLOWED):
                        os.unlink(name, dir_fd=d)
                    os.fsync(d)
            finally:
                os.close(d)
            if mode == 'rollback':
                os.rmdir(os.path.basename(BASE), dir_fd=parent)
                os.fsync(parent)
                require(os.path.basename(BASE) not in os.listdir(parent), 'fixture remains')
    finally:
        os.close(parent)
except (OSError, ValueError, RuntimeError) as error:
    print('REFUSED: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY
