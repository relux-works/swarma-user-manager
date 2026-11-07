"""Synthetic ownership only; real private publication syscalls, no root launch."""
import copy
import errno
import json
import os
import stat
import tempfile
import types
import unittest
from contextlib import contextmanager, ExitStack
from pathlib import Path
from unittest import mock

from test_demo import d, roster, launch_request, MemoryStore, FakeRunner


class ExecutorTests(unittest.TestCase):
    def test_both_exact_pairs_validate_decode_and_launch(self):
        for identity, path in ((d.EXECUTOR_ID, d.EXECUTOR),
                               (d.CODEX_EXECUTOR_ID, d.CODEX_EXECUTOR)):
            with self.subTest(identity=identity):
                r = roster()
                r['executor'].update(id=identity, path=path)
                self.assertEqual(d.validate_roster(r), r)
                request = launch_request()
                request['executor'] = identity
                request, plan = d.decode(d.encoded(request), True)
                store = MemoryStore(r)
                runner = FakeRunner(r, store)
                result = d.launch(r, 1101, request, plan, store, runner, 100.)
                self.assertEqual(result['launch_outcome'], 'receipt_seen')
                self.assertEqual(runner.spawn_count, 1)

    def test_third_near_miss_and_crossed_paths_refuse(self):
        for identity, path in (
                ('swarma-demo-third-executor', '/usr/local/libexec/swarma/swarma-demo-third-executor'),
                ('swarma-demo-codex-executer', d.CODEX_EXECUTOR),
                ('swarma-demo-codex-executor ', d.CODEX_EXECUTOR),
                ('Swarma-demo-codex-executor', d.CODEX_EXECUTOR),
                (d.CODEX_EXECUTOR_ID, d.EXECUTOR),
                (d.EXECUTOR_ID, d.CODEX_EXECUTOR),
                (d.CODEX_EXECUTOR_ID, d.CODEX_EXECUTOR + '/.'),
                ([], d.EXECUTOR)):
            with self.subTest(identity=identity, path=path):
                r = roster()
                r['executor'].update(id=identity, path=path)
                with self.assertRaises(d.Refusal) as refusal:
                    d.validate_roster(r)
                self.assertEqual(refusal.exception.code, 'executor_not_approved')
                if identity not in (d.EXECUTOR_ID, d.CODEX_EXECUTOR_ID):
                    request = launch_request()
                    request['executor'] = identity
                    with self.assertRaises(d.Refusal) as refusal:
                        d.decode(d.encoded(request), True)
                    self.assertEqual(refusal.exception.code, 'executor_not_approved')

    def test_approved_request_cannot_select_other_roster_executor(self):
        r, request = roster(), launch_request()
        request['executor'] = d.CODEX_EXECUTOR_ID
        store = MemoryStore(r)
        runner = FakeRunner(r, store)
        with self.assertRaises(d.Refusal) as refusal:
            d.launch(r, 1101, request, b'opaque', store, runner, 100.)
        self.assertEqual(refusal.exception.code, 'executor_not_approved')
        self.assertEqual(runner.spawn_count, 0)
        self.assertEqual(store.writes, [])


class LaunchRecordTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        # Only the trust boundary is synthetic. The writer has no test path or
        # alternate ownership switch; fixtures redirect its two fixed opens.
        with tempfile.TemporaryDirectory() as private, ExitStack() as patches:
            parent = Path(private)
            records = parent / 'launch-records'
            records.mkdir(mode=0o700)
            trusted = roster()
            row = trusted['accounts'][0]
            plan = b'opaque\x00\xff'
            request = launch_request(plan)
            actual_fstat = os.fstat

            def ownership(fd):
                info = actual_fstat(fd)
                return types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode,
                                             st_nlink=info.st_nlink)

            def opened(path, **kwargs):
                self.assertEqual(kwargs, dict(mode=0o755, directory=True))
                self.assertIn(path, ('/run/swarma-demo', d.LAUNCH_RECORDS))
                return os.open(parent if path == '/run/swarma-demo' else records,
                               os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

            patches.enter_context(mock.patch.object(d, 'protected', side_effect=opened))
            patches.enter_context(mock.patch.object(d, 'load_roster', return_value=trusted))
            patches.enter_context(mock.patch.object(d.os, 'getuid', return_value=0))
            patches.enter_context(mock.patch.object(d.os, 'geteuid', return_value=0))
            patches.enter_context(mock.patch.object(d.os, 'fstat', side_effect=ownership))
            yield parent, records, trusted, row, request, plan

    def test_exact_schema_digest_permissions_single_link_and_no_overwrite(self):
        with self.fixture() as (parent, records, r, row, request, plan):
            d.write_launch_record(r, row, request, plan)
            path = records / 'EX-fixture.json'
            expected = dict(execution_id='EX-fixture', uid=30000, generation='1' * 32,
                            plan_sha256=d.digest(plan), boot_id=r['boot_id'])
            self.assertEqual(json.loads(path.read_bytes()), expected)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(path.stat().st_nlink, 1)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                d.write_launch_record(r, row, request, plan)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(sorted(x.name for x in parent.iterdir()), ['launch-records'])

    def test_id_grammar_rejects_paths_unicode_newline_and_overlong(self):
        for identity in ('', '.', '..', '../outside', '/outside', 'x/y', 'x\\y',
                         'x\x00', 'x\n', 'é', '-prefix', 'a' * 65, True):
            with self.subTest(identity=identity), self.fixture() as (_, records, r, row, request, plan):
                request['execution_id'] = identity
                with self.assertRaises(d.Refusal):
                    d.write_launch_record(r, row, request, plan)
                self.assertEqual(list(records.iterdir()), [])
        for identity in ('A', 'a' * 64, 'Z9._-'):
            with self.subTest(identity=identity), self.fixture() as (_, records, r, row, request, plan):
                request['execution_id'] = identity
                d.write_launch_record(r, row, request, plan)
                self.assertTrue((records / (identity + '.json')).is_file())

    def test_trusted_origin_and_exact_plan_binding(self):
        for change in ('roster', 'row', 'plan', 'executor', 'runtime', 'nonroot'):
            with self.subTest(change=change), self.fixture() as (_, records, trusted, row, request, plan):
                r = copy.deepcopy(trusted)
                row = copy.deepcopy(row)
                if change == 'roster':
                    r['boot_id'] = '22222222-2222-2222-2222-222222222222'
                elif change == 'row':
                    row['uid'] += 1
                elif change == 'plan':
                    plan += b'changed'
                elif change == 'executor':
                    request['executor'] = d.CODEX_EXECUTOR_ID
                with ExitStack() as patches:
                    if change == 'runtime':
                        patches.enter_context(mock.patch.object(d, 'load_roster', side_effect=d.Refusal('qualification_required')))
                    if change == 'nonroot':
                        patches.enter_context(mock.patch.object(d.os, 'geteuid', return_value=1000))
                    with self.assertRaises(d.Refusal):
                        d.write_launch_record(r, row, request, plan)
                self.assertEqual(list(records.iterdir()), [])

    def test_temporary_and_final_symlinks_are_never_followed_or_replaced(self):
        for collision in ('temporary', 'final', 'temporary-file'):
            with self.subTest(collision=collision), self.fixture() as (parent, records, r, row, request, plan):
                outside = parent / 'outside'
                outside.write_bytes(b'preserve')
                path = parent / '.EX-fixture.launch-new' if collision.startswith('temporary') else records / 'EX-fixture.json'
                if collision == 'temporary-file':
                    path.write_bytes(b'crash reservation')
                else:
                    path.symlink_to(outside)
                with self.assertRaises(FileExistsError):
                    d.write_launch_record(r, row, request, plan)
                self.assertEqual(outside.read_bytes(), b'preserve')
                if collision == 'temporary-file':
                    self.assertEqual(path.read_bytes(), b'crash reservation')
                else:
                    self.assertTrue(path.is_symlink())

    def test_publication_order_and_no_partial_directory_entries(self):
        with self.fixture() as (parent, records, r, row, request, plan):
            actual_rename, actual_sync = d.rename_exclusive, os.fsync
            events = []
            def sync(fd):
                events.append('directory-sync' if stat.S_ISDIR(os.stat('/proc/self/fd/' + str(fd)).st_mode) else 'file-sync')
                return actual_sync(fd)
            def rename(*args):
                self.assertEqual(list(records.iterdir()), [])
                staging = parent / '.EX-fixture.launch-new'
                self.assertEqual(stat.S_IMODE(staging.stat().st_mode), 0o444)
                self.assertEqual(events, ['file-sync'])
                events.append('publish')
                result = actual_rename(*args)
                self.assertEqual((records / 'EX-fixture.json').stat().st_nlink, 1)
                return result
            with mock.patch.object(d, 'rename_exclusive', side_effect=rename), mock.patch.object(d.os, 'fsync', side_effect=sync):
                d.write_launch_record(r, row, request, plan)
            self.assertEqual(events, ['file-sync', 'publish', 'directory-sync', 'directory-sync'])

    def test_faults_clean_only_unpublished_temporary_and_retain_published_authority(self):
        for fault in ('write', 'chmod', 'file-sync', 'close', 'rename', 'destination-sync', 'staging-sync'):
            with self.subTest(fault=fault), self.fixture() as (parent, records, r, row, request, plan), ExitStack() as patches:
                error = OSError(errno.EIO, 'synthetic publication fault')
                actual_sync, actual_close = os.fsync, os.close
                syncs = 0
                def sync(fd):
                    nonlocal syncs
                    syncs += 1
                    fail_at = {'file-sync': 1, 'destination-sync': 2, 'staging-sync': 3}.get(fault)
                    if syncs == fail_at:
                        raise error
                    return actual_sync(fd)
                def close(fd):
                    regular = stat.S_ISREG(os.stat('/proc/self/fd/' + str(fd)).st_mode)
                    actual_close(fd)
                    if regular:
                        raise error
                patches.enter_context(mock.patch.object(d.os, 'fsync', side_effect=sync))
                if fault in ('write', 'chmod'):
                    patches.enter_context(mock.patch.object(d.os, 'write' if fault == 'write' else 'fchmod', side_effect=error))
                if fault == 'close':
                    patches.enter_context(mock.patch.object(d.os, 'close', side_effect=close))
                if fault == 'rename':
                    patches.enter_context(mock.patch.object(d, 'rename_exclusive', side_effect=error))
                with self.assertRaises(OSError):
                    d.write_launch_record(r, row, request, plan)
                self.assertFalse((parent / '.EX-fixture.launch-new').exists())
                self.assertEqual((records / 'EX-fixture.json').exists(), fault in ('destination-sync', 'staging-sync'))

    def test_short_writes_and_nonroot_metadata_refusal(self):
        with self.fixture() as (_, records, r, row, request, plan):
            actual_write = os.write
            with mock.patch.object(d.os, 'write', side_effect=lambda fd, data: actual_write(fd, data[:3])):
                d.write_launch_record(r, row, request, plan)
            self.assertEqual(json.loads((records / 'EX-fixture.json').read_bytes())['plan_sha256'], d.digest(plan))
        for metadata in (dict(st_uid=1000), dict(st_gid=1000), dict(st_nlink=2), dict(st_mode=stat.S_IFIFO | 0o600)):
            with self.subTest(metadata=metadata), self.fixture() as (parent, records, r, row, request, plan):
                info = dict(st_uid=0, st_gid=0, st_nlink=1, st_mode=stat.S_IFREG | 0o600)
                info.update(metadata)
                with mock.patch.object(d.os, 'fstat', return_value=types.SimpleNamespace(**info)):
                    with self.assertRaises(d.Refusal):
                        d.write_launch_record(r, row, request, plan)
                self.assertEqual(list(records.iterdir()), [])
                self.assertFalse((parent / '.EX-fixture.launch-new').exists())

    def test_racing_destination_creation_is_exclusive(self):
        with self.fixture() as (parent, records, r, row, request, plan):
            actual_rename = d.rename_exclusive
            def race(*args):
                (records / 'EX-fixture.json').write_bytes(b'first publisher')
                return actual_rename(*args)
            with mock.patch.object(d, 'rename_exclusive', side_effect=race):
                with self.assertRaises(FileExistsError):
                    d.write_launch_record(r, row, request, plan)
            self.assertEqual((records / 'EX-fixture.json').read_bytes(), b'first publisher')
            self.assertFalse((parent / '.EX-fixture.launch-new').exists())

    def test_real_protected_walk_refuses_links_unowned_and_writable_directories(self):
        for fault in ('none', 'parent-link', 'leaf-link', 'writable-parent', 'writable-leaf', 'unowned-parent', 'acl'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as private, ExitStack() as patches:
                root = Path(private)
                parent = root / 'run/swarma-demo'
                records = parent / 'launch-records'
                records.mkdir(parents=True, mode=0o755)
                records.chmod(0o755)
                parent.chmod(0o755)
                (root / 'run').chmod(0o755)
                if fault in ('parent-link', 'leaf-link'):
                    path = parent if fault == 'parent-link' else records
                    moved = path.with_name(path.name + '-real')
                    path.rename(moved)
                    path.symlink_to(moved, target_is_directory=True)
                if fault == 'writable-parent':
                    parent.chmod(0o775)
                if fault == 'writable-leaf':
                    records.chmod(0o777)
                actual_open, actual_fstat = os.open, os.fstat
                def opened(path, flags, *args, **kwargs):
                    return actual_open(root if path == '/' else path, flags, *args, **kwargs)
                def ownership(fd):
                    info = actual_fstat(fd)
                    name = os.readlink('/proc/self/fd/' + str(fd))
                    return types.SimpleNamespace(st_uid=1000 if fault == 'unowned-parent' and name == str(parent) else 0,
                                                 st_gid=0, st_nlink=info.st_nlink, st_mode=info.st_mode)
                patches.enter_context(mock.patch.object(d.os, 'open', side_effect=opened))
                patches.enter_context(mock.patch.object(d.os, 'fstat', side_effect=ownership))
                if fault == 'acl':
                    patches.enter_context(mock.patch.object(d.os, 'listxattr', return_value=['system.posix_acl_default']))
                if fault == 'none':
                    fd = d.protected(d.LAUNCH_RECORDS, mode=0o755, directory=True)
                    os.close(fd)
                else:
                    with self.assertRaises((d.Refusal, OSError)):
                        d.protected(d.LAUNCH_RECORDS, mode=0o755, directory=True)
