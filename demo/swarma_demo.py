#!/usr/bin/python3 -IS
"""Disposable Linux demo only. Not the station helper or a Curator executor.

Install identical, root-owned copies at the two fixed entrypoints after review.
No import of repository code occurs in an installed privileged invocation.
"""
import base64
import ctypes
import copy
import datetime
import errno
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import select
import signal
import stat
import time
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass

BASE = '7d705966aa92acaebea2d55060dcb84ddf7e5031'
ROSTER = '/etc/swarma-demo/roster.json'
STATE = '/var/lib/swarma-demo-user-manager'
RECEIPT_ROOT = '/run/swarma-demo/receipts'
LAUNCHER = '/usr/local/libexec/swarma/swarma-user-launcher'
HELPER = '/usr/local/libexec/swarma/swarma-user-manager'
EXECUTOR = '/usr/local/libexec/swarma/swarma-demo-executor'
EXECUTOR_ID = 'swarma-demo-executor'
CODEX_EXECUTOR_ID = 'swarma-demo-codex-executor'
CODEX_EXECUTOR = '/usr/local/libexec/swarma/swarma-demo-codex-executor'
EXECUTORS = {EXECUTOR_ID: EXECUTOR, CODEX_EXECUTOR_ID: CODEX_EXECUTOR}
LAUNCH_RECORDS = '/run/swarma-demo/launch-records'
UID_MIN, UID_MAX = 30000, 30019
PLAN_MAX, LAUNCH_MAX, STOP_MAX = 48 * 1024, 80 * 1024, 16 * 1024
OUTPUT_MAX, COPY_MAX, ENTRY_MAX = 1024 * 1024, 256 * 1024 * 1024, 20000
INTAKE, RECEIPT, STOP_WHOLE, QUIET, FINAL_SCAN = 5.0, 10.0, 45.0, 2.0, 5.0
IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
GEN = re.compile(r'[0-9a-f]{32}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
BOOT = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
NAMES = ('swarma-demo-01', 'swarma-demo-02', 'swarma-demo-03')
OPERATOR = {'name': 'agent', 'uid': 1001, 'gid': 1001}
DISPATCHER_NAME, DISPATCHER_ID = 'swarma-demo-dispatcher', 1101
DISPATCHER_STATE = '/var/lib/swarma-demo-dispatcher'
DISPATCHER_HOME = '/var/lib/swarma-demo-dispatcher-home'
SUDO_ENTRYPOINTS = ('/usr/bin/sudo', '/usr/bin/sudo-rs')
# Frozen Git entries only; never follow or flatten these links.
COPY_EXCLUSIONS = dict.fromkeys(('.claude/skills/swarma-user-manager',
                                '.codex/skills/swarma-user-manager'),
                               'de4c19a2c482d19fed882eca9fd6df09de71040b')
STATE_MAX, EVENT_MAX = 128 * 1024, 256


class Refusal(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class NativeFailure(Refusal):
    def __init__(self, detail):
        super().__init__('state_unavailable')
        self.detail = detail


def refuse(code):
    raise Refusal(code)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def closed(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        refuse('request_invalid')


def integer(value, lo, hi):
    return type(value) is int and lo <= value <= hi


def identifier(value):
    return type(value) is str and IDENT.fullmatch(value) is not None


def generation(value):
    return type(value) is str and GEN.fullmatch(value) is not None and value != '0' * 32


def bounded_json(data, cap, list_max):
    if len(data) > cap:
        refuse('request_too_large')

    def pairs(items):
        result = {}
        for key, val in items:
            if key in result:
                refuse('request_invalid')
            result[key] = val
        return result

    def walk(value, depth=0):
        if depth > 12:
            refuse('request_invalid')
        if type(value) is str and '\x00' in value:
            refuse('request_invalid')
        if type(value) is str and len(value) > 64 * 1024:
            refuse('request_too_large')
        if type(value) is dict:
            for key, val in value.items():
                walk(key, depth + 1)
                walk(val, depth + 1)
        if type(value) is list:
            if len(value) > list_max:
                refuse('request_invalid')
            for val in value:
                walk(val, depth + 1)

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: refuse('request_invalid'))
        walk(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        refuse('request_invalid')


def strict(data, cap):
    # Request/roster intake keeps its original 64-element bound.
    return bounded_json(data, cap, 64)


def state_decode(data):
    # Protected internal evidence has a separate byte/event bound. Requests
    # cannot select this codec, and Store.write validates it before publication.
    return bounded_json(data, STATE_MAX, EVENT_MAX)


def decode(data, launch):
    obj = strict(data, LAUNCH_MAX if launch else STOP_MAX)
    if launch:
        closed(obj, ('v', 'op', 'request_id', 'generation', 'execution_id', 'epoch', 'executor', 'plan'))
        if obj['op'] != 'launch.start' or not integer(obj['epoch'], 1, 2**53 - 1):
            refuse('request_invalid')
        if type(obj['executor']) is not str or obj['executor'] not in EXECUTORS:
            refuse('executor_not_approved')
        raw = obj['plan']
        if type(raw) is not str or len(raw) > 64 * 1024:
            refuse('request_too_large')
        try:
            plan = base64.b64decode(raw, validate=True)
        except (ValueError, UnicodeError):
            refuse('request_invalid')
        if len(plan) > PLAN_MAX:
            refuse('request_too_large')
        if base64.b64encode(plan).decode() != raw:
            refuse('request_invalid')
    else:
        closed(obj, ('v', 'op', 'request_id', 'args'))
        if obj['op'] != 'exec.stop':
            refuse('caller_role_not_permitted')
        closed(obj['args'], ('generation', 'execution_id'), ('grace_seconds',))
        if not integer(obj['args'].get('grace_seconds', 10), 0, 30):
            refuse('request_invalid')
        plan = None
    target = obj if launch else obj['args']
    if type(obj['v']) is not int or obj['v'] != 1 or not identifier(obj['request_id']) or not identifier(target['execution_id']) or not generation(target['generation']):
        refuse('request_invalid')
    return obj, plan


def intake(fd, cap, started):
    os.set_blocking(fd, False)
    data = bytearray()
    while True:
        left = INTAKE - (time.monotonic() - started)
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            refuse('request_timeout')
        try:
            part = os.read(fd, min(8192, cap + 1 - len(data)))
        except BlockingIOError:
            continue
        if not part:
            return bytes(data)
        data.extend(part)
        if len(data) > cap:
            refuse('request_too_large')


def close_except(keep):
    # /proc is mandatory; failure is fatal, never a guessed RLIMIT upper bound.
    fds = [int(n) for n in os.listdir('/proc/self/fd') if n.isdecimal()]
    for fd in fds:
        if fd not in keep:
            try:
                os.close(fd)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise


def no_acl(fd):
    if any(name.startswith('system.posix_acl_') for name in os.listxattr(fd)):
        refuse('state_unavailable')


def protected(path, flags=os.O_RDONLY, mode=None, owner=0, directory=False, group=None):
    """Walk from /, refusing links and writable/unowned ancestors, on descriptors."""
    if not path.startswith('/') or os.path.normpath(path) != path or path == '/':
        refuse('path_is_link')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        root_info = os.fstat(parent)
        if root_info.st_uid != 0 or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) & 0o022:
            refuse('state_unavailable')
        no_acl(parent)
        for part in path.split('/')[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                refuse('state_unavailable')
            no_acl(parent)
        fd = os.open(path.rsplit('/', 1)[-1], flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
        try:
            info = os.fstat(fd)
            if info.st_uid != owner or info.st_gid != (owner if group is None else group) or (mode is not None and stat.S_IMODE(info.st_mode) != mode):
                refuse('state_unavailable')
            if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
                refuse('state_unavailable')
            no_acl(fd)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def read_bounded(fd, cap):
    data = bytearray()
    while len(data) <= cap:
        part = os.read(fd, min(65536, cap + 1 - len(data)))
        if not part:
            return bytes(data)
        data.extend(part)
    refuse('state_unavailable')


def manifest(source, deadline, destination=None, owner=None, expected=None):
    """Descriptor-relative copy with two exact frozen source-link exclusions.

    The copied regular content digest excludes these links; the source manifest
    records their exact Git path/mode/blob. An account-owned copy permits none.
    """
    root = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    total, count, entries, excluded = 0, 0, [], []
    seen = set()
    try:
        def walk(parent, relative, depth):
            nonlocal total, count
            if depth > 64 or time.monotonic() >= deadline:
                refuse('copy_bound_exceeded')
            with os.scandir(parent) as stream:
                names = []
                for item in stream:
                    if not relative and item.name == '.git':
                        continue
                    names.append(item.name)
                    if len(names) > ENTRY_MAX:
                        refuse('copy_bound_exceeded')
            for name in sorted(names):
                count += 1
                if count > ENTRY_MAX or time.monotonic() >= deadline:
                    refuse('copy_bound_exceeded')
                path = relative + '/' + name if relative else name
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if expected is not None and path not in expected:
                    refuse('copy_source_revision')
                seen.add(path)
                if stat.S_ISLNK(before.st_mode):
                    if owner is not None or path not in COPY_EXCLUSIONS:
                        refuse('path_is_link')
                    raw = os.fsencode(os.readlink(name, dir_fd=parent))
                    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw,
                                        usedforsecurity=False).hexdigest()
                    after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns, after.st_ctime_ns) != (before.st_dev, before.st_ino, before.st_mode, before.st_mtime_ns, before.st_ctime_ns):
                        refuse('copy_changed')
                    if blob != COPY_EXCLUSIONS[path]:
                        refuse('path_is_link')
                    if expected is not None and expected[path] != ('120000', blob):
                        refuse('copy_source_revision')
                    excluded.append({'path': path, 'mode': '120000', 'blob': blob,
                                     'status': 'excluded-by-freeze'})
                    continue
                if path in COPY_EXCLUSIONS:
                    refuse('copy_changed')
                if not stat.S_ISDIR(before.st_mode) and not stat.S_ISREG(before.st_mode):
                    refuse('copy_special_file')
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | (os.O_DIRECTORY if stat.S_ISDIR(before.st_mode) else 0), dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino, info.st_mode) != (before.st_dev, before.st_ino, before.st_mode):
                        refuse('copy_changed')
                    no_acl(fd)
                    if owner is not None and (info.st_uid != owner or info.st_gid != owner or stat.S_IMODE(info.st_mode) & 0o077):
                        refuse('copy_changed')
                    if stat.S_ISDIR(info.st_mode):
                        if expected is not None and expected[path][0] != '040000':
                            refuse('copy_source_revision')
                        if destination:
                            os.mkdir(os.path.join(destination, path), 0o700)
                        entries.append([path, 'directory'])
                        walk(fd, path, depth + 1)
                    else:
                        if info.st_nlink != 1:
                            refuse('copy_hardlink')
                        total += info.st_size
                        if total > COPY_MAX:
                            refuse('copy_bound_exceeded')
                        hasher, size = hashlib.sha256(), 0
                        blob_hasher = hashlib.sha1(b'blob ' + str(info.st_size).encode() + b'\0', usedforsecurity=False)
                        out = None
                        if destination:
                            out = os.open(os.path.join(destination, path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o700 if info.st_mode & stat.S_IXUSR else 0o600)
                        try:
                            while True:
                                if time.monotonic() >= deadline:
                                    refuse('copy_bound_exceeded')
                                chunk = os.read(fd, 65536)
                                if not chunk:
                                    break
                                size += len(chunk)
                                if size > info.st_size:
                                    refuse('copy_changed')
                                hasher.update(chunk)
                                blob_hasher.update(chunk)
                                if out is not None:
                                    view = memoryview(chunk)
                                    while view:
                                        written = os.write(out, view)
                                        if written <= 0:
                                            refuse('copy_changed')
                                        view = view[written:]
                            after = os.fstat(fd)
                            if size != info.st_size or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                                refuse('copy_changed')
                            mode = '100755' if info.st_mode & stat.S_IXUSR else '100644'
                            if expected is not None and expected[path] != (mode, blob_hasher.hexdigest()):
                                refuse('copy_source_revision')
                            if out is not None:
                                os.fsync(out)
                        finally:
                            if out is not None:
                                os.close(out)
                        entries.append([path, 'executable' if info.st_mode & stat.S_IXUSR else 'file', size, hasher.hexdigest()])
                finally:
                    os.close(fd)
        walk(root, '', 0)
        if expected is not None and seen != set(expected):
            refuse('copy_source_revision')
        return {'digest': digest(encoded(entries)), 'entries': count, 'bytes': total, 'excluded': excluded}
    finally:
        os.close(root)


def current_boot():
    with open('/proc/sys/kernel/random/boot_id', 'r', encoding='ascii') as stream:
        return stream.read().strip()


def validate_roster(obj):
    closed(obj, ('format', 'source_revision', 'boot_id', 'operator', 'dispatcher', 'executor', 'runtime', 'accounts'))
    if obj['format'] != 'swarma-user-manager demo-roster/1' or obj['source_revision'] != BASE or type(obj['boot_id']) is not str or not BOOT.fullmatch(obj['boot_id']):
        refuse('state_unavailable')
    closed(obj['operator'], ('name', 'uid', 'gid'))
    if obj['operator'] != OPERATOR or any(type(obj['operator'][key]) is not int for key in ('uid', 'gid')):
        refuse('state_unavailable')
    d = obj['dispatcher']
    closed(d, ('name', 'uid', 'gid', 'principal', 'generation'))
    if d['name'] != DISPATCHER_NAME or d['principal'] != DISPATCHER_NAME or not generation(d['generation']) or type(d['uid']) is not int or type(d['gid']) is not int or d['uid'] != DISPATCHER_ID or d['gid'] != DISPATCHER_ID:
        refuse('state_unavailable')
    if d['name'] in NAMES + (OPERATOR['name'],) or d['uid'] == obj['operator']['uid'] or UID_MIN <= d['gid'] <= UID_MAX or UID_MIN <= d['uid'] <= UID_MAX or UID_MIN <= obj['operator']['uid'] <= UID_MAX:
        refuse('state_unavailable')
    ex = obj['executor']
    closed(ex, ('id', 'path', 'sha256'))
    if type(ex['id']) is not str or ex['id'] not in EXECUTORS or ex['path'] != EXECUTORS[ex['id']] or type(ex['sha256']) is not str or not SHA.fullmatch(ex['sha256']):
        refuse('executor_not_approved')
    runtime = obj['runtime']
    closed(runtime, ('admitted', 'inventory_qualified', 'creation_exclusion_qualified', 'interpreter_qualified'))
    if any(type(value) is not bool for value in runtime.values()):
        refuse('state_unavailable')
    rows = obj['accounts']
    if type(rows) is not list or len(rows) != 3:
        refuse('state_unavailable')
    names, ids, gens = set(), set(), {d['generation']}
    for row in rows:
        closed(row, ('name', 'uid', 'gid', 'generation', 'owning_dispatcher', 'home', 'workspace', 'copy_digest'))
        name = row['name']
        if name not in NAMES or name in names or not integer(row['uid'], UID_MIN, UID_MAX) or row['gid'] != row['uid'] or type(row['gid']) is not int or row['uid'] in ids:
            refuse('state_unavailable')
        if not generation(row['generation']) or row['generation'] in gens or row['owning_dispatcher'] != d['principal']:
            refuse('target_not_owned')
        if row['home'] != '/srv/swarma-demo/home/' + name or row['workspace'] != '/srv/swarma-demo/work/' + name or type(row['copy_digest']) is not str or not SHA.fullmatch(row['copy_digest']):
            refuse('state_unavailable')
        names.add(name)
        ids.add(row['uid'])
        gens.add(row['generation'])
    return obj


def load_roster():
    fd = protected(ROSTER, mode=0o644)
    try:
        obj = validate_roster(strict(read_bounded(fd, 48 * 1024), 48 * 1024))
    finally:
        os.close(fd)
    if obj['boot_id'] != current_boot() or not all(obj['runtime'].values()):
        refuse('qualification_required')
    return obj


def sudo_executable(image):
    """Pin an image reached only through a fixed sudo entrypoint.

    Alternatives links may select the image, but every link and containing
    directory must remain root-owned. Never trust a caller's executable path.
    """
    for entry in SUDO_ENTRYPOINTS:
        path = entry
        for _ in range(8):
            if len(path) > 4095 or not path.startswith('/'):
                refuse('not_invoked_by_sudo')
            directory, leaf = os.path.split(path)
            parent = protected(directory, directory=True)
            try:
                if stat.S_IMODE(os.fstat(parent).st_mode) & 0o022:
                    refuse('not_invoked_by_sudo')
                info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    if info.st_uid != 0 or info.st_gid != 0:
                        refuse('not_invoked_by_sudo')
                    link = os.readlink(leaf, dir_fd=parent)
                    after = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                    if (info.st_dev, info.st_ino, info.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_ctime_ns):
                        refuse('not_invoked_by_sudo')
                    path = os.path.normpath(os.path.join(directory, link))
                    continue
            except FileNotFoundError:
                break
            finally:
                os.close(parent)
            if path == image:
                return protected(path)
            break
    refuse('not_invoked_by_sudo')


def verified_invocation(argv, environ):
    if argv:
        refuse('argv_not_allowed')
    if os.getuid() != 0 or os.geteuid() != 0:
        refuse('not_root')
    text = environ.get('SUDO_UID', '')
    if not text.isascii() or not text.isdecimal() or not integer(int(text), 1, 2**32 - 2):
        refuse('not_invoked_by_sudo')
    parent = os.getppid()
    proc = '/proc/' + str(parent)
    name = os.readlink(proc + '/exe')
    if os.stat(proc).st_uid != 0:
        refuse('not_invoked_by_sudo')
    expected = sudo_executable(name)
    actual = os.open(proc + '/exe', os.O_RDONLY | os.O_CLOEXEC)
    try:
        a, b = os.fstat(expected), os.fstat(actual)
        if a.st_uid != 0 or a.st_gid != 0 or not stat.S_ISREG(a.st_mode) or stat.S_IMODE(a.st_mode) & 0o022 or not a.st_mode & 0o111 or (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) or os.getppid() != parent:
            refuse('not_invoked_by_sudo')
    finally:
        os.close(expected)
        os.close(actual)
    return int(text)


def authorize(roster, uid):
    if uid != roster['dispatcher']['uid']:
        refuse('caller_role_not_permitted')
    return roster['dispatcher']


def target(roster, gen):
    for row in roster['accounts']:
        if row['generation'] == gen:
            return row
    refuse('generation_not_active')


def rename_exclusive(source, name, destination, final):
    # Linux RENAME_NOREPLACE: ordinary rename would overwrite authority. There
    # is no fallback to a check-then-rename or a transient two-link publication.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        refuse('state_unavailable')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source, os.fsencode(name), destination, os.fsencode(final), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def write_launch_record(roster, row, request, plan):
    """Publish authority from the protected current roster and decoded intake.

    Called under transition exclusion with the child behind its root barrier.
    No caller chooses a directory, UID, generation, boot or digest. Published
    authority is retained even if a later barrier/exec/deadline fails.
    """
    if os.getuid() != 0 or os.geteuid() != 0:
        refuse('not_root')
    trusted = load_roster()
    if trusted != roster or target(trusted, request['generation']) != row:
        refuse('target_not_owned')
    checked, decoded = decode(encoded(request), True)
    if checked['executor'] != trusted['executor']['id'] or decoded != plan:
        refuse('executor_not_approved' if checked['executor'] != trusted['executor']['id'] else 'request_invalid')
    value = {'execution_id': checked['execution_id'], 'uid': row['uid'],
             'generation': row['generation'], 'plan_sha256': digest(decoded),
             'boot_id': trusted['boot_id']}
    data = encoded(value)
    # Stage outside the enumerated consumer directory. No partial/temporary
    # record (or two-link intermediate) can invalidate an already pinned launch.
    staging = protected('/run/swarma-demo', mode=0o755, directory=True)
    directory, fd, created, published = None, None, False, False
    temporary, final = '.' + checked['execution_id'] + '.launch-new', checked['execution_id'] + '.json'
    try:
        directory = protected(LAUNCH_RECORDS, mode=0o755, directory=True)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=staging)
        created = True
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
            refuse('state_unavailable')
        no_acl(fd)
        view = memoryview(data)
        while view:
            size = os.write(fd, view)
            if size <= 0:
                refuse('state_unavailable')
            view = view[size:]
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        closing, fd = fd, None
        os.close(closing)
        rename_exclusive(staging, temporary, directory, final)
        published = True
        created = False
        os.fsync(directory)
        os.fsync(staging)
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            try:
                if created and not published:
                    os.unlink(temporary, dir_fd=staging)
                    os.fsync(staging)
            finally:
                try:
                    if directory is not None:
                        os.close(directory)
                finally:
                    os.close(staging)


def receipt_directory_metadata(info):
    return (stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
            info.st_gid == DISPATCHER_ID and stat.S_IMODE(info.st_mode) == 0o750)


def receipt_file_metadata(info):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
            info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o644 and
            info.st_nlink == 1)


def receipt_directory(gen):
    if not generation(gen):
        refuse('request_invalid')
    root = protected(RECEIPT_ROOT, mode=0o750, directory=True, group=DISPATCHER_ID)
    try:
        child = os.open(gen, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=root)
        try:
            if not receipt_directory_metadata(os.fstat(child)):
                refuse('state_unavailable')
            no_acl(child)
            return child
        except BaseException:
            os.close(child)
            raise
    finally:
        os.close(root)


class Store:
    def __init__(self):
        self.fd = protected(STATE, mode=0o700, directory=True)

    def close(self):
        os.close(self.fd)

    @contextmanager
    def locked(self, name='transition.lock'):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                refuse('state_unavailable')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                refuse('state_conflict')
            yield
        finally:
            os.close(fd)

    def read(self, gen):
        fd = os.open(gen + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                refuse('state_unavailable')
            return state_decode(read_bounded(fd, STATE_MAX))
        finally:
            os.close(fd)

    def write(self, gen, value):
        data = encoded(value)
        if len(data) > STATE_MAX:
            refuse('state_unavailable')
        state_decode(data)  # never publish evidence our bounded reader rejects
        name = gen + '.new'
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    refuse('state_unavailable')
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(name, gen + '.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)


    def receipt(self, gen, execution, value):
        if not identifier(execution):
            refuse('request_invalid')
        directory = receipt_directory(gen)
        temporary = execution + '.new'
        try:
            try:
                os.stat(execution + '.json', dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                refuse('execution_already_started')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=directory)
            try:
                # The invocation may have inherited another effective group.
                # Pin root:root explicitly before exposing the receipt.
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o644)
                if not receipt_file_metadata(os.fstat(fd)):
                    refuse('state_unavailable')
                no_acl(fd)
                data = encoded(value)
                if len(data) > 4096:
                    refuse('state_unavailable')
                while data:
                    size = os.write(fd, data)
                    if size <= 0:
                        refuse('state_unavailable')
                    data = data[size:]
                os.fsync(fd)
            finally:
                os.close(fd)
            # The root-only transition lock excludes competing publications.
            # A crash leaves the intent/temporary reserved, never a new start.
            rename_exclusive(directory, temporary, directory, execution + '.json')
            os.fsync(directory)
        finally:
            os.close(directory)


@dataclass(frozen=True)
class Process:
    pid: int
    start_time: int
    session_id: int
    uids: tuple
    gids: tuple


def process(pid):
    root = '/proc/' + str(pid)
    with open(root + '/stat', 'r', encoding='ascii') as stream:
        raw = stream.read(8192)
    # comm can contain ')' and spaces. Fields after the last ')' start at #3.
    fields = raw[raw.rfind(')') + 2:].split()
    with open(root + '/status', 'r', encoding='ascii') as stream:
        status = dict(line.split(':', 1) for line in stream if ':' in line)
    return Process(pid, int(fields[19]), int(fields[3]), tuple(map(int, status['Uid'].split())), tuple(map(int, status['Gid'].split())))


class Native:
    def __init__(self, roster):
        self.roster = roster
        self.clock = time.monotonic
        self.sleep = time.sleep
        self.launch_evidence = []

    def check(self, row):
        now = load_roster()
        if now != self.roster or target(now, row['generation']) != row:
            refuse('target_not_owned')
        d = now['dispatcher']
        entry = pwd.getpwnam(d['name'])
        if (entry.pw_uid, entry.pw_gid, entry.pw_dir, entry.pw_shell) != (d['uid'], d['gid'], DISPATCHER_HOME, '/usr/sbin/nologin') or any(d['name'] in item.gr_mem for item in grp.getgrall()):
            refuse('caller_role_not_permitted')
        primary = grp.getgrgid(d['gid'])
        if primary.gr_name != d['name'] or primary.gr_mem:
            refuse('caller_role_not_permitted')
        home = protected(DISPATCHER_HOME, mode=0o700, owner=d['uid'], directory=True)
        os.close(home)
        operator = pwd.getpwnam(OPERATOR['name'])
        if (operator.pw_uid, operator.pw_gid) != (now['operator']['uid'], now['operator']['gid']):
            refuse('caller_role_not_permitted')
        entry = pwd.getpwnam(row['name'])
        if (entry.pw_uid, entry.pw_gid, entry.pw_dir, entry.pw_shell) != (row['uid'], row['gid'], row['home'], '/usr/sbin/nologin'):
            refuse('generation_not_active')
        if any(row['name'] in item.gr_mem for item in grp.getgrall()):
            refuse('generation_not_active')
        primary = grp.getgrgid(row['gid'])
        if primary.gr_name != row['name'] or primary.gr_mem:
            refuse('generation_not_active')

    def launch_check(self, row, deadline):
        self.check(row)
        for directory in (row['home'], row['workspace']):
            fd = protected(directory, mode=0o700, owner=row['uid'], directory=True)
            os.close(fd)
        for name in ('tmp', 'cache'):
            parent = protected(row['home'], mode=0o700, owner=row['uid'], directory=True)
            try:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    if info.st_uid != row['uid'] or info.st_gid != row['gid'] or stat.S_IMODE(info.st_mode) != 0o700:
                        refuse('state_unavailable')
                    no_acl(fd)
                finally:
                    os.close(fd)
            finally:
                os.close(parent)
        private_copy = manifest(row['workspace'] + '/source', deadline, owner=row['uid'])
        if private_copy['digest'] != row['copy_digest']:
            refuse('copy_changed')
        for name in ('identity-witness.json', 'stdout.log', 'stderr.log'):
            try:
                os.lstat(row['workspace'] + '/' + name)
            except FileNotFoundError:
                continue
            refuse('execution_already_started')
        if self.clock() >= deadline:
            refuse('request_timeout')

    def scan(self, row, deadline):
        self.check(row)
        found, complete = [], True
        # root in the admitted initial PID/mount namespace is a qualification gate;
        # this sanity check does not certify host-wide visibility by itself.
        if os.readlink('/proc/self/ns/pid') != os.readlink('/proc/1/ns/pid'):
            return [], False
        entries = os.scandir('/proc')
        try:
            count = 0
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                count += 1
                if count > 131072 or self.clock() >= deadline:
                    return found, False
                try:
                    member = process(int(entry.name))
                    if row['uid'] in member.uids:
                        if member.uids != (row['uid'],) * 4 or member.gids != (row['gid'],) * 4:
                            complete = False
                        else:
                            found.append(member)
                except FileNotFoundError:
                    # A disappearing entry is not an unreadable extant process.
                    continue
                except (OSError, ValueError, KeyError, IndexError):
                    complete = False
        finally:
            entries.close()
        return found, complete

    def receipt_matches(self, row, receipt):
        if receipt['boot_id'] != current_boot():
            return False
        try:
            actual = process(receipt['pid'])
        except FileNotFoundError:
            return True  # only the root is absent; UID-wide scan remains mandatory
        except (OSError, ValueError, KeyError, IndexError):
            return False
        return (actual.start_time == receipt['start_time'] and actual.session_id == receipt['session_id'] and actual.uids == (row['uid'],) * 4 and actual.gids == (row['gid'],) * 4)

    def signal(self, row, member, number, *, deadline=None, grace_end=None):
        self.check(row)
        try:
            fd = os.pidfd_open(member.pid, 0)
        except ProcessLookupError:
            return 'gone'
        try:
            if process(member.pid) != member or member.uids != (row['uid'],) * 4 or member.gids != (row['gid'],) * 4:
                return 'identity_changed'
            # Recheck after NSS, pidfd and incarnation work, immediately before
            # the native action. The caller durably records KILL before retrying.
            now = self.clock()
            if deadline is not None and now >= deadline:
                return 'deadline_expired'
            if number == signal.SIGTERM and grace_end is not None and now >= grace_end:
                return 'grace_expired'
            signal.pidfd_send_signal(fd, number, None, 0)
            return 'sent'
        except ProcessLookupError:
            return 'gone'
        except FileNotFoundError:
            return 'gone'
        except OSError:
            return 'signal_failed'
        finally:
            os.close(fd)

    def spawn(self, row, request, plan, persist_receipt, deadline):
        return spawn(self, row, request, plan, persist_receipt, deadline)


def new_record(roster, row, request, started):
    return {'format': 'swarma-user-manager demo-attempt/1', 'source_revision': BASE,
            'boot_id': roster['boot_id'], 'account': row, 'dispatcher': roster['dispatcher'],
            'request': request, 'request_digest': digest(encoded(request)),
            'accepted_at': utc(), 'launch_started_mono': started,
            'launch_elapsed_seconds': None, 'receipt': None, 'launch_outcome': 'unknown',
            'stop': None}


def launch(roster, uid, request, plan, store, backend, started):
    record, observed = launch_locked(roster, uid, request, plan, store, backend, started)
    # The transition context has exited, including its descriptor close. These
    # are invocation-only facts; no durable success or corrective write follows.
    record = copy.deepcopy(record)
    record['launch_outcome'] = observed
    return complete(record, True, backend.clock())


def launch_locked(roster, uid, request, plan, store, backend, started):
    authorize(roster, uid)
    if request['executor'] != roster['executor']['id']:
        refuse('executor_not_approved')
    row = target(roster, request['generation'])
    deadline = started + RECEIPT
    with store.locked():
        backend.check(row)
        try:
            old = store.read(row['generation'])
        except FileNotFoundError:
            refuse('state_unavailable')
        reservation = {'format': 'swarma-user-manager demo-reservation/1', 'account': row,
                       'dispatcher': roster['dispatcher'], 'boot_id': roster['boot_id']}
        if old != reservation:
            if old['request_digest'] != digest(encoded(request)) or old['account'] != row or old['boot_id'] != roster['boot_id']:
                refuse('execution_already_started')
            # Earlier versions could durably cache an unchecked final success.
            # No installed record proves completion of its own publication.
            old['launch_outcome'] = 'unknown'
            old['launch_elapsed_seconds'] = None
            return old, 'unknown'  # preserved attempt/receipt only; never a second start
        backend.launch_check(row, deadline)
        members, complete = backend.scan(row, min(deadline, backend.clock() + FINAL_SCAN))
        if not complete or members:
            refuse('uid_not_clean')
        if backend.clock() >= deadline:
            refuse('request_timeout')
        record = new_record(roster, row, request, started)
        store.write(row['generation'], record)  # irreversible intent before fork

        def persist(receipt):
            store.receipt(row['generation'], request['execution_id'], receipt)
            record['receipt'] = receipt
            store.write(row['generation'], record)  # while child is still root

        try:
            record['launch_outcome'] = backend.spawn(row, request, plan, persist, deadline)
        except (OSError, Refusal, ValueError) as exc:
            record['launch_outcome'] = 'unknown'
            record['launch_failure'] = exc.detail if isinstance(exc, NativeFailure) else exc.code if isinstance(exc, Refusal) else {'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None)}
        record['native_evidence'] = getattr(backend, 'launch_evidence', [])
        observed = record['launch_outcome']
        # A durable value cannot attest the completion time of its own write.
        # Keep recovery conservative; only this invocation can observe that the
        # final publication completed in time. No success-then-rollback window.
        record['launch_outcome'] = 'unknown'
        record['launch_elapsed_seconds'] = None
        record['launch_publication'] = {'status': 'unconfirmed',
                                        'observed_elapsed_seconds': backend.clock() - started}
        store.write(row['generation'], record)
        return record, observed


def stop(roster, uid, request, store, backend, started=None):
    record, finished_at = stop_locked(roster, uid, request, store, backend, started)
    # Both the transition lock and the outer stop lease have been released.
    record = copy.deepcopy(record)
    evidence = record['stop']
    if finished_at is not None:
        evidence['outcome'] = 'absent'
        evidence['finished_at'] = finished_at
    return complete(record, False, backend.clock())


def complete(record, launching, finished):
    """Refresh invocation-only facts; never promote an unresolved result."""
    if launching:
        origin = record['launch_started_mono']
        record['launch_elapsed_seconds'] = finished - origin
        if finished >= origin + RECEIPT:
            record['launch_outcome'] = 'unknown'
    else:
        evidence = record['stop']
        evidence['elapsed_seconds'] = finished - evidence['started_mono']
        stop_bounds(evidence, finished)
        if evidence['deadline_missed'] or evidence['final_scan_deadline_missed']:
            evidence['outcome'] = 'pending'
            evidence['finished_at'] = None
    return record


@contextmanager
def stop_transition(store, backend, deadline):
    # Receipt files become visible while launch still owns transition exclusion.
    # Retry acquisition only, never the protected body or any physical effect.
    with ExitStack() as held:
        while True:
            if backend.clock() >= deadline:
                refuse('request_timeout')
            try:
                held.enter_context(store.locked())
                if backend.clock() >= deadline:
                    refuse('request_timeout')
                break
            except Refusal as exc:
                if exc.code != 'state_conflict':
                    raise
            remaining = deadline - backend.clock()
            if remaining <= 0:
                refuse('request_timeout')
            backend.sleep(min(0.01, remaining))
        yield


def stop_locked(roster, uid, request, store, backend, started=None):
    authorize(roster, uid)
    args = request['args']
    row = target(roster, args['generation'])
    admitted = backend.clock() if started is None else started
    # Per-account stop lease is distinct from the transition lock. No transition
    # lock is held during census, signals, grace waits or quiet-window waits.
    with store.locked(row['generation'] + '.stop.lock'):
        with stop_transition(store, backend, admitted + STOP_WHOLE):
            record = store.read(row['generation'])
            if record['account'] != row or record['dispatcher'] != roster['dispatcher'] or record['boot_id'] != roster['boot_id']:
                refuse('target_not_owned')
            if record['request']['execution_id'] != args['execution_id'] or record['receipt'] is None:
                refuse('state_conflict')
            prior = record['stop']
            if prior is not None:
                if prior['request'] != request:
                    refuse('request_id_conflict')
                if prior['outcome'] == 'absent' or 'completion_publication' in prior:
                    # Even historical optimistic absence is unconfirmed here.
                    # Recovery never promotes a pre-write timestamp to a final
                    # publication time, and never signals a completed candidate.
                    prior['outcome'] = 'pending'
                    prior['finished_at'] = None
                    return record, None
            else:
                prior = {'request': request, 'started_at': utc(), 'started_mono': admitted,
                         'grace_seconds': args.get('grace_seconds', 10), 'kill_mono': None,
                         'outcome': 'pending', 'events': [], 'signalled': 0, 'killed': 0,
                         'last_scan_complete': False, 'remaining': None,
                         'finished_at': None, 'elapsed_seconds': None}
                record['stop'] = prior
                store.write(row['generation'], record)
        return stop_loop(roster, row, record, store, backend)


def stop_loop(roster, row, record, store, backend):
    evidence = record['stop']
    origin = evidence['started_mono']
    deadline = origin + STOP_WHOLE
    grace_end = origin + evidence['grace_seconds']
    entry_end = min(deadline, evidence['kill_mono'] + FINAL_SCAN) if evidence['kill_mono'] is not None else deadline
    late_at_entry = backend.clock() >= entry_end
    quiet_since = None
    sent = set()
    # At most 512 bounded census steps. Time and storage bounds are independent.
    for _ in range(512):
        backend.check(row)
        if not backend.receipt_matches(row, record['receipt']):
            evidence['outcome'] = 'pending'
            if len(evidence['events']) < EVENT_MAX:
                evidence['events'].append({'at': utc(), 'elapsed_seconds': backend.clock() - origin, 'failure': 'receipt_identity_changed'})
            break
        now = backend.clock()
        scan_end = min(deadline, now + FINAL_SCAN)
        if evidence['kill_mono'] is not None:
            scan_end = min(scan_end, evidence['kill_mono'] + FINAL_SCAN)
        # Even an expired continuation narrows once, without renewing grace or
        # claiming timely absence. Never initiate an unbounded late census.
        if now >= scan_end:
            evidence['outcome'] = 'pending'
            evidence['deadline_missed'] = now >= deadline
            evidence['final_scan_deadline_missed'] = evidence['kill_mono'] is not None and now >= evidence['kill_mono'] + FINAL_SCAN
            if late_at_entry:
                late_narrow(row, record, store, backend)
            break
        members, complete = backend.scan(row, scan_end)
        now = backend.clock()
        if len(members) > 64:
            complete = False  # bounded evidence cannot establish complete absence
        evidence['last_scan_complete'] = complete
        evidence['remaining'] = len(members) if complete else None
        event = {'at': utc(), 'elapsed_seconds': now - origin, 'complete': complete,
                 'members': [dict(pid=m.pid, start_time=m.start_time, session_id=m.session_id, uids=m.uids, gids=m.gids) for m in members[:64]],
                 'member_count': len(members), 'signals': []}
        if len(evidence['events']) >= EVENT_MAX:
            evidence['outcome'] = 'pending'
            break  # no unrecorded ordinary signal batch after evidence exhaustion
        evidence['events'].append(event)
        for member in members[:64]:
            now = backend.clock()
            action_end = min(deadline, evidence['kill_mono'] + FINAL_SCAN) if evidence['kill_mono'] is not None else deadline
            if now >= action_end:
                complete = False
                break
            number = signal.SIGKILL if now >= grace_end else signal.SIGTERM
            key = (member.pid, member.start_time, int(number))
            if key in sent:
                continue
            if number == signal.SIGKILL and evidence['kill_mono'] is None:
                evidence['kill_mono'] = backend.clock()
                with store.locked():
                    store.write(row['generation'], record)  # original KILL bound before action
            # Persistence can consume the remainder of the original budget.
            action_end = min(deadline, evidence['kill_mono'] + FINAL_SCAN) if evidence['kill_mono'] is not None else deadline
            if backend.clock() >= action_end:
                complete = False
                break
            outcome = backend.signal(row, member, number, deadline=action_end, grace_end=grace_end)
            event['signals'].append({'pid': member.pid, 'start_time': member.start_time, 'signal': int(number), 'outcome': outcome})
            sent.add(key)
            if outcome == 'sent':
                evidence['killed' if number == signal.SIGKILL else 'signalled'] += 1
            elif outcome not in ('gone',):
                complete = False
        if members or not complete:
            quiet_since = None
        elif quiet_since is None:
            quiet_since = backend.clock()
        now = backend.clock()
        final_end = min(deadline, (evidence['kill_mono'] + FINAL_SCAN) if evidence['kill_mono'] is not None else deadline)
        if complete and not members and quiet_since is not None and now - quiet_since >= QUIET and now < final_end:
            evidence['outcome'] = 'absent'
            evidence['finished_at'] = utc()
            break
        with store.locked():
            store.write(row['generation'], record)
        now = backend.clock()  # state persistence also consumes the same budget
        if now >= final_end:
            break
        backend.sleep(min(0.25, final_end - now))
    candidate = evidence['outcome'] == 'absent'
    finished_at = evidence['finished_at'] if candidate else None
    # Persist no terminal success. If publication fails or the service crashes,
    # a reload can only see pending; it cannot depend on a corrective write.
    evidence['outcome'] = 'pending'
    evidence['finished_at'] = None
    evidence['elapsed_seconds'] = None
    if candidate:
        evidence['completion_publication'] = {'status': 'unconfirmed',
                                             'observed_elapsed_seconds': backend.clock() - origin}
    with store.locked():
        store.write(row['generation'], record)
    return record, finished_at


def stop_bounds(evidence, now):
    evidence['deadline_missed'] = now >= evidence['started_mono'] + STOP_WHOLE
    evidence['final_scan_deadline_missed'] = (evidence['kill_mono'] is not None and
                                            now >= evidence['kill_mono'] + FINAL_SCAN)


def late_narrow(row, record, store, backend):
    """No new grace/census/absence claim after any applicable original bound.

    Revalidate and KILL previously recorded safe incarnations immediately, with
    a bounded five-second work allowance, retaining the missed original bound.
    This allowance never changes the operation's original deadline or outcome.
    """
    evidence = record['stop']
    receipt = record['receipt']
    candidates = {(receipt['pid'], receipt['start_time']): Process(receipt['pid'], receipt['start_time'], receipt['session_id'], (row['uid'],) * 4, (row['gid'],) * 4)}
    for event in reversed(evidence['events']):
        for item in event.get('members', []):
            if len(candidates) >= 64:
                break
            candidates[(item['pid'], item['start_time'])] = Process(item['pid'], item['start_time'], item['session_id'], tuple(item['uids']), tuple(item['gids']))
        if len(candidates) >= 64:
            break
    end = backend.clock() + FINAL_SCAN
    if evidence['kill_mono'] is None:
        evidence['kill_mono'] = backend.clock()
        with store.locked():
            store.write(row['generation'], record)
    event = {'at': utc(), 'elapsed_seconds': backend.clock() - evidence['started_mono'],
             'failure': 'original_bound_missed', 'late_narrowing': True, 'signals': []}
    if len(evidence['events']) >= EVENT_MAX:
        return  # retain original evidence; no signal without a recording slot
    evidence['events'].append(event)
    for member in candidates.values():
        if backend.clock() >= end:
            break
        result = backend.signal(row, member, signal.SIGKILL, deadline=end)
        event['signals'].append({'pid': member.pid, 'start_time': member.start_time,
                                 'signal': int(signal.SIGKILL), 'outcome': result})
        if result == 'sent':
            evidence['killed'] += 1
    with store.locked():
        store.write(row['generation'], record)


def sealed_plan(plan):
    if len(plan) > PLAN_MAX:
        refuse('request_too_large')
    fd = os.memfd_create('swarma-demo-plan', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(plan)
        while view:
            size = os.write(fd, view)
            if size <= 0:
                refuse('state_unavailable')
            view = view[size:]
        seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        ro = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_CLOEXEC)
        if fcntl.fcntl(ro, fcntl.F_GET_SEALS) != seals:
            os.close(ro)
            refuse('state_unavailable')
        return ro
    finally:
        os.close(fd)


def wait_read(fd, deadline, cap=4096):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
        refuse('request_timeout')
    return os.read(fd, cap)


def read_barrier(fd, deadline, expected):
    value = wait_read(fd, deadline)
    if value != expected:
        try:
            detail = strict(value, 4096)
            closed(detail, ('stage', 'type', 'errno'))
        except Refusal:
            detail = {'stage': 'barrier', 'type': 'unexpected_status', 'errno': None}
        raise NativeFailure(detail)


def drop(row):
    libc = ctypes.CDLL(None, use_errno=True)
    def prctl(option, arg=0):
        if libc.prctl(option, arg, 0, 0, 0) != 0:
            refuse('privilege_drop_failed')
    # Clear ambient and bounding capabilities while still privileged. The
    # inheritable set must be empty before proceeding; no inherited authority.
    with open('/proc/self/status', encoding='ascii') as stream:
        status = dict(line.split(':', 1) for line in stream if ':' in line)
    if int(status['CapInh'], 16):
        refuse('privilege_drop_failed')
    prctl(47, 4)  # PR_CAP_AMBIENT_CLEAR_ALL
    with open('/proc/sys/kernel/cap_last_cap', encoding='ascii') as stream:
        last = int(stream.read())
    if not 0 <= last < 64:
        refuse('privilege_drop_failed')
    for cap in range(last + 1):
        prctl(24, cap)  # PR_CAPBSET_DROP
    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    os.setgroups([])
    os.setresgid(row['gid'], row['gid'], row['gid'])
    os.setresuid(row['uid'], row['uid'], row['uid'])
    if os.getresuid() != (row['uid'],) * 3 or os.getresgid() != (row['gid'],) * 3 or os.getgroups():
        refuse('privilege_drop_failed')
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        refuse('privilege_drop_failed')
    with open('/proc/self/status', encoding='ascii') as stream:
        status = dict(line.split(':', 1) for line in stream if ':' in line)
    if any(int(status[key], 16) for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb', 'CapBnd')):
        refuse('privilege_drop_failed')


def drain(readers, workspace):
    # Trusted fixed code under the demo UID. The executor gets neither these
    # descriptors nor a privileged writer. Output files are mutable demo data.
    close_except(set(readers))
    files, counts = {}, {}
    try:
        for fd, name in readers.items():
            path = workspace + '/' + name
            files[fd] = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            counts[fd] = 0
        while readers:
            ready, _, _ = select.select(list(readers), [], [])
            for fd in ready:
                data = os.read(fd, 65536)
                if not data:
                    os.fsync(files[fd])
                    os.close(files.pop(fd))
                    os.close(fd)
                    del readers[fd]
                    continue
                kept = data[:max(0, OUTPUT_MAX - counts[fd])]
                view = memoryview(kept)
                while view:
                    size = os.write(files[fd], view)
                    if size <= 0:
                        raise OSError('output write failed')
                    view = view[size:]
                counts[fd] += len(kept)
    finally:
        for fd in files.values():
            os.close(fd)


def spawn(backend, row, request, plan, persist, deadline):
    ex = backend.roster['executor']
    exe = protected(ex['path'], mode=0o755)
    planfd = None
    descriptors = []
    child = None
    try:
        body = read_bounded(exe, 16 * 1024 * 1024)
        if not body.startswith(b'\x7fELF') or digest(body) != ex['sha256']:
            refuse('executable_digest_mismatch')
        os.lseek(exe, 0, os.SEEK_SET)
        home = protected(row['home'], mode=0o700, owner=row['uid'], directory=True)
        descriptors.append(home)
        planfd = sealed_plan(plan)
        gate_r, gate_w = os.pipe2(os.O_CLOEXEC)
        status_r, status_w = os.pipe2(os.O_CLOEXEC)
        out_r, out_w = os.pipe2(os.O_CLOEXEC)
        err_r, err_w = os.pipe2(os.O_CLOEXEC)
        descriptors.extend((gate_r, gate_w, status_r, status_w, out_r, out_w, err_r, err_w))
        if time.monotonic() >= deadline:
            refuse('request_timeout')
        child = os.fork()
        if child == 0:
            error_status = status_w
            stage = 'session'
            try:
                os.close(gate_w)
                os.close(status_r)
                os.setsid()
                os.write(status_w, b'root\n')
                if wait_read(gate_r, deadline, 1) != b'R':
                    os._exit(126)
                os.fchdir(home)
                os.umask(0o077)
                stage = 'drop'
                drop(row)
                # Close root handles before reporting drop, including inherited
                # transition/store descriptors. Parent still holds exclusion.
                close_except({0, 1, 2, exe, planfd, gate_r, status_w, out_r, out_w, err_r, err_w})
                os.write(status_w, b'dropped\n')
                if wait_read(gate_r, deadline, 1) != b'E':
                    os._exit(126)
                stage = 'output'
                drainer = os.fork()
                if drainer == 0:
                    try:
                        drain({out_r: 'stdout.log', err_r: 'stderr.log'}, row['workspace'])
                        os._exit(0)
                    except BaseException:
                        os._exit(125)
                os.dup2(out_w, 1, inheritable=True)
                os.dup2(err_w, 2, inheritable=True)
                null = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
                os.dup2(null, 0, inheritable=True)
                # FD3 may currently be an internal handle: move the executable
                # away first and preserve all sources before dup2 overwrites it.
                safe_exe = fcntl.fcntl(exe, fcntl.F_DUPFD_CLOEXEC, 10)
                safe_status = fcntl.fcntl(status_w, fcntl.F_DUPFD_CLOEXEC, 10)
                error_status = safe_status
                os.dup2(planfd, 3, inheritable=True)
                os.lseek(3, 0, os.SEEK_SET)
                close_except({0, 1, 2, 3, safe_exe, safe_status})
                env = {'HOME': row['home'], 'USER': row['name'], 'LOGNAME': row['name'],
                       'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TMPDIR': row['home'] + '/tmp'}
                # ELF only: CLOEXEC handle consumed by fexecve/execveat and not
                # inherited by the image. No interpreter-script FD exception.
                stage = 'exec'
                os.execve(safe_exe, [ex['path']], env)
            except BaseException as exc:
                try:
                    os.write(error_status, encoded({'stage': stage, 'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None)}) + b'\n')
                except OSError:
                    pass
                os._exit(127)
        os.close(gate_r)
        descriptors.remove(gate_r)
        os.close(status_w)
        descriptors.remove(status_w)
        read_barrier(status_r, deadline, b'root\n')
        backend.launch_evidence.append({'stage': 'session', 'at': utc(), 'monotonic_seconds': time.monotonic()})
        member = process(child)
        if member.uids != (0, 0, 0, 0) or member.session_id != child:
            return 'unknown'
        receipt = {'execution_id': request['execution_id'], 'epoch': request['epoch'],
                   'pid': child, 'start_time': member.start_time,
                   'boot_id': current_boot(), 'session_id': member.session_id}
        persist(receipt)
        backend.launch_evidence.append({'stage': 'receipt_persisted', 'at': utc(), 'monotonic_seconds': time.monotonic()})
        write_launch_record(backend.roster, row, request, plan)
        backend.launch_evidence.append({'stage': 'launch_record_published', 'at': utc(), 'monotonic_seconds': time.monotonic()})
        if time.monotonic() >= deadline:
            refuse('request_timeout')
        os.write(gate_w, b'R')
        read_barrier(status_r, deadline, b'dropped\n')
        actual = process(child)
        if actual.start_time != member.start_time or actual.uids != (row['uid'],) * 4 or actual.gids != (row['gid'],) * 4:
            return 'unknown'
        backend.launch_evidence.append({'stage': 'drop_verified', 'at': utc(), 'monotonic_seconds': time.monotonic()})
        if time.monotonic() >= deadline:
            refuse('request_timeout')
        os.write(gate_w, b'E')
        # EOF means the CLOEXEC status pipe closed. It is not readiness or work
        # success: the separate executor identity witness must be read later.
        read_barrier(status_r, deadline, b'')
        return 'receipt_seen'
    finally:
        # Closing the gate stops a child waiting at either barrier. A dropped or
        # exec'd child remains reserved and is reconciled by exec.stop.
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass
        if planfd is not None:
            os.close(planfd)
        os.close(exe)
        if child and child > 0:
            try:
                found, status = os.waitpid(child, os.WNOHANG)
                if found:
                    backend.launch_evidence.append({'stage': 'child_exit_observed', 'at': utc(), 'monotonic_seconds': time.monotonic(), 'pid': found, 'exit': os.waitstatus_to_exitcode(status)})
            except ChildProcessError:
                pass


def response(request_id, record, launching):
    if launching:
        if record['launch_outcome'] == 'receipt_seen' and record['receipt'] is not None:
            return {'request_id': request_id, 'ok': True, 'result': record['receipt'], 'state': 'receipt_seen'}
        return {'request_id': request_id, 'ok': False, 'error': {'code': 'state_unavailable', 'message': 'Launch unknown; preserve attempt and reconcile.'}}
    evidence = record['stop']
    if evidence['outcome'] == 'absent':
        return {'request_id': request_id, 'ok': True, 'result': {'execution_id': record['request']['execution_id'], 'stopped_at': evidence['finished_at'], 'receipt': {'signalled': evidence['signalled'], 'killed': evidence['killed'], 'remaining': 0}}, 'state': 'stopped'}
    return {'request_id': request_id, 'ok': False, 'error': {'code': 'processes_remain', 'message': 'Stop pending; preserve original attempt and deadlines.'}}


def main(argv=None):
    started = time.monotonic()
    request_id = None
    store = None
    answer = None
    try:
        try:
            import sys
            args = sys.argv[1:] if argv is None else argv
            entry = os.path.abspath(sys.argv[0])
            if entry not in (LAUNCHER, HELPER):
                refuse('qualification_required')
            close_except({0, 1, 2})
            uid = verified_invocation(args, os.environ)
            os.environ.clear()
            os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8')
            os.chdir('/')
            os.umask(0o077)
            roster = load_roster()
            authorize(roster, uid)
            launching = entry == LAUNCHER
            request, plan = decode(intake(0, LAUNCH_MAX if launching else STOP_MAX, started), launching)
            request_id = request['request_id']
            store = Store()
            backend = Native(roster)
            record = launch(roster, uid, request, plan, store, backend, started) if launching else stop(roster, uid, request, store, backend, started)
        finally:
            if store is not None:
                store.close()
    except Refusal as exc:
        answer = {'request_id': request_id, 'ok': False, 'error': {'code': exc.code, 'message': 'Demo request refused.'}}
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        answer = {'request_id': request_id, 'ok': False, 'error': {'code': 'state_unavailable', 'message': 'Demo evidence unavailable; reconcile manually.'}}
    try:
        os.set_blocking(1, False)
        if answer is None:
            # Prepare both wire alternatives before the final clock sample.
            # Serialization and stdout setup consume the original budgets too.
            candidate = response(request_id, record, launching)
            candidate_wire = encoded(candidate) + b'\n'
            unresolved = copy.deepcopy(record)
            if launching:
                unresolved['launch_outcome'] = 'unknown'
            else:
                unresolved['stop']['outcome'] = 'pending'
                unresolved['stop']['finished_at'] = None
            pending = response(request_id, unresolved, launching)
            pending_wire = encoded(pending) + b'\n'
            complete(record, launching, backend.clock())
            timely = (record['launch_outcome'] == 'receipt_seen' if launching
                      else record['stop']['outcome'] == 'absent')
            answer, wire = (candidate, candidate_wire) if timely else (pending, pending_wire)
        else:
            wire = encoded(answer) + b'\n'
    except (Refusal, OSError, ValueError, KeyError, TypeError, IndexError, RecursionError):
        # A preparation failure cannot emit a partially prepared success.
        answer = {'request_id': request_id, 'ok': False, 'error': {'code': 'state_unavailable', 'message': 'Demo response unavailable; reconcile manually.'}}
        try:
            wire = encoded(answer) + b'\n'
        except (Refusal, OSError, ValueError, TypeError, RecursionError):
            return 1
    try:
        if os.write(1, wire) != len(wire):
            return 1
    except OSError:
        return 1  # lost/partial response is unknown, never a retry permit
    return 0 if answer['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
