"""Real source I/O with explicitly synthetic root/group metadata; no root run."""
import errno
import json
import os
import stat
import tempfile
import types
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from test_demo import d, roster


class ReceiptRouteTests(unittest.TestCase):
    gen = '1' * 32

    @contextmanager
    def fixture(self, fault=None):
        with tempfile.TemporaryDirectory() as private, ExitStack() as patches:
            root = Path(private)
            receipts = root / d.RECEIPT_ROOT[1:]
            generation = receipts / self.gen
            generation.mkdir(parents=True, mode=0o750)
            generation.chmod(0o750)
            receipts.chmod(0o750)
            for path in generation.parents:
                if path == receipts:
                    continue
                path.chmod(0o755)
                if path == root:
                    break
            state = root / 'private-state'
            state.mkdir(mode=0o700)
            store = d.Store.__new__(d.Store)
            store.fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            actual_open, actual_fstat = os.open, os.fstat
            if fault == 'root-writable':
                receipts.chmod(0o770)
            if fault == 'generation-writable':
                generation.chmod(0o770)

            def opened(path, flags, *args, **kwargs):
                return actual_open(root if path == '/' else path, flags, *args, **kwargs)

            def metadata(fd):
                info = actual_fstat(fd)
                path = Path(os.readlink('/proc/self/fd/' + str(fd)))
                group = 1101 if path in (receipts, generation) else 0
                owner, mode, links = 0, info.st_mode, info.st_nlink
                if fault == 'nonroot-directory' and path == generation:
                    owner = 1001
                if stat.S_ISREG(mode):
                    if fault == 'nonroot-file':
                        owner = 1001
                    if fault == 'private-file':
                        mode = stat.S_IFREG | 0o600
                    if fault == 'wrong-file-group':
                        group = 1101
                    if fault == 'hardlink':
                        links = 2
                return types.SimpleNamespace(st_uid=owner, st_gid=group, st_mode=mode,
                                             st_nlink=links)

            patches.enter_context(mock.patch.object(d.os, 'open', side_effect=opened))
            patches.enter_context(mock.patch.object(d.os, 'fstat', side_effect=metadata))
            chown = patches.enter_context(mock.patch.object(d.os, 'fchown'))
            try:
                yield store, root, receipts, generation, chown
            finally:
                store.close()

    def value(self):
        return dict(execution_id='EX-receipt', epoch=1, pid=42, start_time=900,
                    boot_id=roster()['boot_id'], session_id=42)

    def test_positive_real_walk_writer_and_dispatcher_modes(self):
        self.assertFalse(d.RECEIPT_ROOT.startswith(d.STATE + '/'))
        with self.fixture() as (store, root, receipts, generation, chown):
            value = self.value()
            store.receipt(self.gen, 'EX-receipt', value)
            path = generation / 'EX-receipt.json'
            self.assertEqual(json.loads(path.read_bytes()), value)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(receipts.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(generation.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE((root / 'private-state').stat().st_mode), 0o700)
            self.assertEqual(list((root / 'private-state').iterdir()), [])
            chown.assert_called_once()
            self.assertEqual(chown.call_args.args[1:], (0, 0))
            fd = d.os.open(path, os.O_RDONLY)
            try:
                self.assertTrue(d.receipt_file_metadata(d.os.fstat(fd)))
            finally:
                os.close(fd)
            with self.assertRaises(d.Refusal):
                store.receipt(self.gen, 'EX-receipt', value)
            self.assertEqual(json.loads(path.read_bytes()), value)

    def test_actual_writer_refuses_bad_directory_and_file_metadata(self):
        for fault in ('root-writable', 'generation-writable', 'nonroot-directory',
                      'nonroot-file', 'private-file', 'wrong-file-group', 'hardlink'):
            with self.subTest(fault=fault), self.fixture(fault) as (store, _, _, generation, _):
                with self.assertRaises(d.Refusal):
                    store.receipt(self.gen, 'EX-receipt', self.value())
                self.assertFalse((generation / 'EX-receipt.json').exists())

    def test_missing_generation_is_not_created_by_first_launch(self):
        with self.fixture() as (store, _, _, generation, _):
            generation.rmdir()
            with self.assertRaises(FileNotFoundError):
                store.receipt(self.gen, 'EX-receipt', self.value())
            self.assertFalse(generation.exists())

    def test_links_and_invalid_components_refuse(self):
        with self.fixture() as (store, root, _, generation, _):
            other = root / 'other'
            other.mkdir(mode=0o750)
            generation.rmdir()
            generation.symlink_to(other, target_is_directory=True)
            with self.assertRaises(OSError):
                store.receipt(self.gen, 'EX-receipt', self.value())
            self.assertEqual(list(other.iterdir()), [])
            for gen, execution in (('../escape', 'ok'), (self.gen, '../escape')):
                with self.assertRaises(d.Refusal):
                    store.receipt(gen, execution, self.value())

    def test_real_exclusive_rename_cannot_replace_racing_file(self):
        with self.fixture() as (store, _, _, generation, _):
            rename = d.rename_exclusive
            def race(*args):
                (generation / 'EX-receipt.json').write_bytes(b'first publisher')
                return rename(*args)
            with mock.patch.object(d, 'rename_exclusive', side_effect=race):
                with self.assertRaises(OSError) as refusal:
                    store.receipt(self.gen, 'EX-receipt', self.value())
            self.assertEqual(refusal.exception.errno, errno.EEXIST)
            self.assertEqual((generation / 'EX-receipt.json').read_bytes(), b'first publisher')

    def test_original_sync_failure_is_not_success(self):
        with self.fixture() as (store, _, _, generation, _):
            with mock.patch.object(d.os, 'fsync', side_effect=OSError(errno.EIO, 'synthetic sync fault')):
                with self.assertRaises(OSError):
                    store.receipt(self.gen, 'EX-receipt', self.value())
            self.assertFalse((generation / 'EX-receipt.json').exists())
            self.assertTrue((generation / 'EX-receipt.new').exists())
