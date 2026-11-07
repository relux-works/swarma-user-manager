#!/usr/bin/python3 -IS
"""Recorded, reviewed operator procedure; never invoked by the dispatcher.

Dry-run is the default. --apply is a later, separately admitted VM operation.
Do not run this procedure on a shared host. Admission supplies real pins.
"""
import argparse
import importlib.util
import os
import stat
import subprocess
import sys
import time

# A root operator selects this reviewed procedure, not a repository/plugin entry.
# Installed helpers themselves are standalone and do not import this module.
spec = importlib.util.spec_from_file_location('demo', os.path.join(os.path.dirname(__file__), 'swarma_demo.py'))
demo = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = demo
spec.loader.exec_module(demo)


manifest = demo.manifest


def fixed_env(home):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': home, 'TMPDIR': home,
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_COUNT': '0',
            'GIT_NO_REPLACE_OBJECTS': '1'}


def command(argv, home, timeout=5):
    import selectors
    started = time.monotonic()
    outputs = {'stdout': bytearray(), 'stderr': bytearray()}
    counts = {'stdout': 0, 'stderr': 0}
    proc = subprocess.Popen(argv, env=fixed_env(home), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            close_fds=True, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(proc.stderr, selectors.EVENT_READ, 'stderr')
    timed_out = False
    deadline = started + timeout
    drain_deadline = None
    incomplete = False
    try:
        while selector.get_map() or proc.poll() is None:
            now = time.monotonic()
            if now >= deadline and not timed_out:
                timed_out = True
                try:
                    os.killpg(proc.pid, 9)
                except ProcessLookupError:
                    pass
                drain_deadline = now + 1
            if drain_deadline is not None and now >= drain_deadline:
                incomplete = bool(selector.get_map()) or proc.poll() is None
                break
            for key, _ in selector.select(min(0.05, max(0, (drain_deadline or deadline) - now))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                name = key.data
                counts[name] += len(chunk)
                outputs[name].extend(chunk[:max(0, demo.OUTPUT_MAX - len(outputs[name]))])
        try:
            code = proc.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            code = None
            incomplete = True
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
    return {'tool': argv[0], 'arguments': argv[1:], 'at': demo.utc(),
            'elapsed_seconds': time.monotonic() - started, 'exit': code,
            'timeout': timed_out, 'drain_incomplete': incomplete,
            'stdout': outputs['stdout'].decode('utf-8', 'replace'),
            'stderr': outputs['stderr'].decode('utf-8', 'replace'),
            'stdout_bytes_drained': counts['stdout'], 'stderr_bytes_drained': counts['stderr'],
            'output_over_cap': any(n > demo.OUTPUT_MAX for n in counts.values())}


def git_args(source):
    return ['/usr/bin/git', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
            '-c', 'credential.helper=', '-c', 'protocol.allow=never', '-C', source]


def frozen_manifest(source, home, log=None):
    # ls-tree reads immutable objects by full revision, never index flags or
    # ignored-file policy. Include trees so empty extra directories also refuse.
    receipt = command(git_args(source) + ['ls-tree', '-r', '-t', '-z', '--full-tree', demo.BASE], home)
    if log is not None:
        log.append(receipt)
    if (receipt['exit'] != 0 or receipt['timeout'] or receipt['drain_incomplete'] or
            receipt['output_over_cap'] or not receipt['stdout'].endswith('\0')):
        demo.refuse('copy_source_revision')
    expected = {}
    for entry in receipt['stdout'][:-1].split('\0'):
        header, path = entry.split('\t', 1)
        mode, kind, blob = header.split(' ')
        if (mode not in ('040000', '100644', '100755', '120000') or
                kind != ('tree' if mode == '040000' else 'blob') or
                not demo.re.fullmatch('[0-9a-f]{40}', blob) or
                not path or path.startswith('/') or path != os.path.normpath(path) or
                '..' in path.split('/') or path in expected or
                any(ord(c) < 32 or ord(c) > 126 for c in path)):
            demo.refuse('copy_source_revision')
        if mode == '120000' and demo.COPY_EXCLUSIONS.get(path) != blob:
            demo.refuse('path_is_link')
        expected[path] = (mode, blob)
        if len(expected) > demo.ENTRY_MAX:
            demo.refuse('copy_bound_exceeded')
    if any(expected.get(path) != ('120000', blob) for path, blob in demo.COPY_EXCLUSIONS.items()):
        demo.refuse('copy_source_revision')
    if expected.get('agents/skills/swarma-user-manager', (None,))[0] != '040000':
        demo.refuse('copy_source_revision')
    return expected


def source_check(source, home, log=None):
    if not os.path.isabs(source) or os.path.realpath(source) != source:
        demo.refuse('path_is_link')
    administration = os.open(source + '/.git', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        # Reject linked worktrees, alternates and local includes before Git reads
        # configuration. The source is an operator's new public clone only.
        for path in ('commondir', 'objects/info/alternates', 'config.worktree'):
            try:
                os.stat(path, dir_fd=administration, follow_symlinks=False)
            except FileNotFoundError:
                continue
            demo.refuse('copy_git_administration')
        fd = os.open('config', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=administration)
        try:
            config = demo.read_bounded(fd, 16 * 1024).decode('utf-8')
        finally:
            os.close(fd)
        if any(word in config.lower() for word in ('include', 'credential', 'fsmonitor', 'hookspath', 'worktree', 'filter', 'sshcommand')):
            demo.refuse('copy_git_administration')
    finally:
        os.close(administration)
    receipts = [command(git_args(source) + ['rev-parse', '--verify', 'HEAD'], home),
                command(git_args(source) + ['status', '--porcelain=v1', '--untracked-files=all'], home)]
    if log is not None:
        log.extend(receipts)
    if receipts[0]['exit'] != 0 or receipts[0]['stdout'].strip() != demo.BASE or receipts[1]['exit'] != 0 or receipts[1]['stdout'] or any(r['timeout'] or r['output_over_cap'] for r in receipts):
        demo.refuse('copy_source_revision')
    objects = frozen_manifest(source, home, log)
    copied = manifest(source, time.monotonic() + 30, expected=objects)
    expected = [{'path': path, 'mode': '120000', 'blob': blob,
                 'status': 'excluded-by-freeze'} for path, blob in sorted(demo.COPY_EXCLUSIONS.items())]
    if copied['excluded'] != expected:
        demo.refuse('copy_source_revision')
    # The real skill directory is regular source content and must remain.
    skill = os.open(source + '/agents/skills/swarma-user-manager',
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    os.close(skill)
    return copied, receipts


def fresh_git(path, home):
    result = command(['/usr/bin/git', '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
                      '-c', 'init.templateDir=', 'init', '--template=', '--initial-branch=demo', path], home)
    if result['exit'] != 0 or result['timeout'] or result['output_over_cap']:
        demo.refuse('copy_git_administration')
    # init has no template hooks, objects, remotes, helpers or inherited global
    # config. Explicit local settings persist for later inert inspection.
    for key, value in (('core.hooksPath', '/dev/null'), ('credential.helper', ''), ('protocol.allow', 'never')):
        item = command(['/usr/bin/git', '-C', path, 'config', '--local', key, value], home)
        if item['exit'] != 0 or item['timeout']:
            demo.refuse('copy_git_administration')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if any(not os.path.isabs(value) or os.path.normpath(value) != value for value in (args.admission, args.source, args.record)):
        parser.error('admission, source and record paths must be absolute and normalized')
    os.umask(0o077)
    report = {'format': 'swarma-user-manager demo-provision/1', 'at': demo.utc(), 'apply': args.apply,
              'source_revision': demo.BASE, 'commands': [], 'outcome': 'refused', 'accounts_changed': False}
    started = time.monotonic()
    # An exclusive record prevents rerun/reuse even after partial mutation. No
    # account, group or home deletion is an automated error-recovery action.
    if args.apply and args.record != '/var/lib/swarma-demo-provision.json':
        demo.refuse('request_invalid')
    fd = os.open(args.record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        admission_fd = demo.protected(args.admission, mode=0o644) if args.apply else os.open(args.admission, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            roster = demo.validate_roster(demo.strict(demo.read_bounded(admission_fd, 48 * 1024), 48 * 1024))
        finally:
            os.close(admission_fd)
        if args.apply:
            caller = demo.verified_invocation([], os.environ)
            if caller != roster['operator']['uid'] or roster['boot_id'] != demo.current_boot() or not all(roster['runtime'].values()):
                demo.refuse('qualification_required')
            admission_fd = demo.protected(args.admission, mode=0o644)
            os.close(admission_fd)
        # This preflight precedes account/directory mutation and verifies both
        # exact frozen exclusions, preserving the real skill source directory.
        import tempfile
        with tempfile.TemporaryDirectory(prefix='demo-operator-', dir=os.environ.get('TMPDIR', '/tmp')) as home:
            os.chmod(home, 0o700)
            copied, receipts = source_check(args.source, home, report['commands'])
            report['copy'] = copied
            if any(row['copy_digest'] != copied['digest'] for row in roster['accounts']):
                demo.refuse('copy_source_revision')
            if not args.apply:
                report['outcome'] = 'preflight_only'
                return 0
            # The full range is reserved for this disposable VM. Refuse any
            # pre-existing identity: no adoption, idempotent creation or reuse.
            if any(demo.UID_MIN <= p.pw_uid <= demo.UID_MAX for p in demo.pwd.getpwall()) or any(demo.UID_MIN <= g.gr_gid <= demo.UID_MAX for g in demo.grp.getgrall()):
                demo.refuse('user_exists_unmanaged')
            for row in roster['accounts']:
                try:
                    demo.pwd.getpwnam(row['name'])
                except KeyError:
                    pass
                else:
                    demo.refuse('user_exists_unmanaged')
                try:
                    demo.grp.getgrnam(row['name'])
                except KeyError:
                    pass
                else:
                    demo.refuse('user_exists_unmanaged')
            # The dispatcher identity is the separately pinned demo service,
            # created only by this admitted operator path. Never adopt/reuse it.
            if any(item.pw_uid == demo.DISPATCHER_ID or item.pw_name == demo.DISPATCHER_NAME for item in demo.pwd.getpwall()) or any(item.gr_gid == demo.DISPATCHER_ID or item.gr_name == demo.DISPATCHER_NAME for item in demo.grp.getgrall()):
                demo.refuse('user_exists_unmanaged')
            for command_line in (['/usr/sbin/groupadd', '--gid', str(demo.DISPATCHER_ID), demo.DISPATCHER_NAME],
                                 ['/usr/sbin/useradd', '--uid', str(demo.DISPATCHER_ID), '--gid', str(demo.DISPATCHER_ID), '--groups', '', '--no-create-home', '--no-user-group', '--no-log-init', '--home-dir', demo.DISPATCHER_HOME, '--shell', '/usr/sbin/nologin', '--password', '!', demo.DISPATCHER_NAME]):
                report['accounts_changed'] = True  # includes uncertain effects
                result = command(command_line, home)
                report['commands'].append(result)
                if result['exit'] != 0 or result['timeout'] or result['output_over_cap']:
                    demo.refuse('account_creation_unknown')
            os.mkdir(demo.DISPATCHER_HOME, 0o700)
            os.chmod(demo.DISPATCHER_HOME, 0o700)
            os.chown(demo.DISPATCHER_HOME, demo.DISPATCHER_ID, demo.DISPATCHER_ID, follow_symlinks=False)
            # State is O_EXCL provisioning ownership. Existing state, including
            # a partial/failed run, is never removed or automatically resumed.
            for parent in ('/srv/swarma-demo', '/srv/swarma-demo/home', '/srv/swarma-demo/work', '/etc/swarma-demo'):
                os.mkdir(parent, 0o755)
                os.chmod(parent, 0o755)
            os.mkdir(demo.STATE, 0o700)
            os.mkdir(demo.STATE + '/receipts', 0o700)
            for row in roster['accounts']:
                reservation = {'format': 'swarma-user-manager demo-reservation/1', 'account': row,
                               'dispatcher': roster['dispatcher'], 'boot_id': roster['boot_id']}
                store = demo.Store()
                try:
                    store.write(row['generation'], reservation)
                    os.mkdir(demo.STATE + '/receipts/' + row['generation'], 0o700)
                finally:
                    store.close()
                for command_line in (['/usr/sbin/groupadd', '--gid', str(row['gid']), row['name']],
                                     ['/usr/sbin/useradd', '--uid', str(row['uid']), '--gid', str(row['gid']), '--groups', '', '--no-create-home', '--no-user-group', '--no-log-init', '--home-dir', row['home'], '--shell', '/usr/sbin/nologin', '--password', '!', row['name']]):
                    result = command(command_line, home)
                    report['commands'].append(result)
                    report['accounts_changed'] = True  # includes uncertain effects
                    if result['exit'] != 0 or result['timeout'] or result['output_over_cap']:
                        demo.refuse('account_creation_unknown')
                for path in (row['home'], row['workspace'], row['home'] + '/tmp', row['home'] + '/cache'):
                    os.mkdir(path, 0o700)
                    os.chmod(path, 0o700)
                    os.chown(path, row['uid'], row['gid'], follow_symlinks=False)
                destination = row['workspace'] + '/source'
                os.mkdir(destination, 0o700)
                actual = manifest(args.source, time.monotonic() + 30, destination,
                                  expected=frozen_manifest(args.source, home, report['commands']))
                if actual != copied:
                    demo.refuse('copy_changed')
                report['commands'].append(fresh_git(destination, home))
                # This tree has never been visible to a live account process;
                # descriptor walk refuses links before changing any ownership.
                chown_private(destination, row['uid'])
            out = os.open(demo.ROSTER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
            try:
                os.fchmod(out, 0o644)
                data = demo.encoded(roster)
                while data:
                    data = data[os.write(out, data):]
                os.fsync(out)
            finally:
                os.close(out)
            report['outcome'] = 'provisioned_not_launched'
            return 0
    except (demo.Refusal, OSError, ValueError, KeyError) as exc:
        report['failure'] = exc.code if isinstance(exc, demo.Refusal) else type(exc).__name__
        return 1
    finally:
        report['finished_at'] = demo.utc()
        report['elapsed_seconds'] = time.monotonic() - started
        data = demo.encoded(report) + b'\n'
        while data:
            size = os.write(fd, data)
            if size <= 0:
                raise OSError('record write failed')
            data = data[size:]
        os.fsync(fd)
        os.close(fd)


def chown_private(path, uid):
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.scandir(root) as stream:
            for entry in stream:
                fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=root)
                try:
                    info = os.fstat(fd)
                    if stat.S_ISDIR(info.st_mode):
                        chown_private(path + '/' + entry.name, uid)
                    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        demo.refuse('copy_changed')
                    os.fchown(fd, uid, uid)
                finally:
                    os.close(fd)
        os.fchown(root, uid, uid)
    finally:
        os.close(root)


if __name__ == '__main__':
    raise SystemExit(main())
