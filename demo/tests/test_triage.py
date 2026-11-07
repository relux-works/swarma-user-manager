"""Offline P1 lifecycle regressions; root identity is synthetic, never acquired."""
import os
import stat
import tempfile
import threading
import time
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
import test_demo as f

d = f.d


class StopAdmissionTests(unittest.TestCase):
    def test_visible_receipt_stop_waits_for_real_launch_flock(self):
        with f.StateTests().fixture() as (disk, root):
            class Store(f.MemoryStore):
                @contextmanager
                def locked(self, name='transition.lock'):
                    with disk.locked(name), super().locked(name):
                        yield
            r = f.roster(); s = Store(r); b = f.FakeRunner(r, s)
            b.clock, b.sleep = time.monotonic, time.sleep
            published, release = threading.Event(), threading.Event()
            original = b.spawn
            failures = []
            def spawn(*args):
                value = original(*args)
                published.set()
                if not release.wait(3):
                    raise AssertionError('fixture release timed out')
                return value
            b.spawn = spawn
            def launching():
                try:
                    d.launch(r, 1101, f.launch_request(), b'opaque', s, b, b.clock())
                except BaseException as exc:
                    failures.append(exc)
            worker = threading.Thread(target=launching)
            worker.start()
            self.assertTrue(published.wait(3))
            self.assertEqual(len(s.receipts), 1)
            self.assertTrue(s.transition)
            timer = threading.Timer(.05, release.set)
            began = b.clock()
            timer.start()
            try:
                result = d.stop(r, 1101, f.stop_request(), s, b, began)
            finally:
                release.set(); worker.join(3); timer.join(3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(result['stop']['outcome'], 'absent')
            self.assertEqual(result['stop']['started_mono'], began)
            self.assertGreaterEqual(result['stop']['elapsed_seconds'], d.QUIET + .05)
            self.assertLess(result['stop']['elapsed_seconds'], d.STOP_WHOLE)
            self.assertEqual(b.spawn_count, 1)

    def test_lock_wait_consumes_original_budget_and_never_retries_body(self):
        for conflicts in (0, 3, 10000):
            with self.subTest(conflicts=conflicts):
                r = f.roster(); s = f.MemoryStore(r); b = f.FakeRunner(r, s)
                d.launch(r, 1101, f.launch_request(), b'opaque', s, b, 100.)
                original = s.locked
                remaining = [conflicts]
                @contextmanager
                def locked(name='transition.lock'):
                    if name == 'transition.lock' and remaining[0]:
                        remaining[0] -= 1
                        d.refuse('state_conflict')
                    with original(name):
                        yield
                s.locked = locked
                if conflicts == 10000:
                    before = len(s.writes)
                    with self.assertRaises(d.Refusal) as exc:
                        d.stop(r, 1101, f.stop_request(), s, b, 99.)
                    self.assertEqual(exc.exception.code, 'request_timeout')
                    self.assertEqual(b.now, 144.)
                    self.assertEqual(len(s.writes), before)
                    self.assertEqual(b.calls, [])
                else:
                    result = d.stop(r, 1101, f.stop_request(), s, b, 99.)
                    self.assertEqual(result['stop']['started_mono'], 99.)
                    self.assertEqual(result['stop']['outcome'], 'absent')
                    self.assertEqual(len(b.calls), 1)
                    self.assertEqual(b.spawn_count, 1)

    def test_lock_body_failure_is_not_retried(self):
        r = f.roster(); s = f.MemoryStore(r); b = f.FakeRunner(r, s)
        d.launch(r, 1101, f.launch_request(), b'opaque', s, b, 100.)
        calls = []
        def read(gen):
            calls.append(gen)
            d.refuse('state_conflict')
        s.read = read
        with self.assertRaises(d.Refusal):
            d.stop(r, 1101, f.stop_request(), s, b)
        self.assertEqual(len(calls), 1)
        self.assertEqual(b.calls, [])


class ParentOriginTests(unittest.TestCase):
    def invoke(self, variant):
        # Actual private links/descriptors, synthetic root metadata. The only
        # parent executable open is redirected to this fixture; nothing execs.
        with tempfile.TemporaryDirectory() as private:
            root = Path(private)
            for name in ('bin', 'alternatives', 'lib'):
                (root/name).mkdir(mode=0o755)
            image = root/'lib'/'sudo'
            image.write_bytes(b'synthetic sudo image')
            image.chmod(0o755)
            other = root/'lib'/'other'
            other.write_bytes(image.read_bytes()); other.chmod(0o755)
            entry = root/'bin'/'sudo'
            alias = root/'alternatives'/'sudo'
            alias.symlink_to('../lib/sudo')
            entry.symlink_to(alias)
            if variant == 'loop':
                alias.unlink(); alias.symlink_to(entry)
            if variant == 'writable-image':
                image.chmod(0o777)
            if variant == 'writable-parent':
                (root/'alternatives').chmod(0o777)
            actual_open, actual_stat, actual_fstat, actual_readlink = os.open, os.stat, os.fstat, os.readlink
            def metadata(info, owner=0):
                return types.SimpleNamespace(st_uid=owner, st_gid=0, st_mode=info.st_mode,
                                             st_dev=info.st_dev, st_ino=info.st_ino,
                                             st_ctime_ns=info.st_ctime_ns, st_nlink=info.st_nlink)
            def inspect(path, *args, **kwargs):
                if path == '/proc/500':
                    return types.SimpleNamespace(st_uid=1 if variant == 'foreign-parent' else 0)
                info = actual_stat(path, *args, **kwargs)
                owner = 1 if variant == 'foreign-link' and stat.S_ISLNK(info.st_mode) else 0
                return metadata(info, owner)
            def opened(path, flags, *args, **kwargs):
                if path == '/proc/500/exe':
                    path = other if variant == 'inode-mismatch' else image
                return actual_open(path, flags, *args, **kwargs)
            def link(path, *args, **kwargs):
                if path == '/proc/500/exe':
                    return str(other if variant == 'arbitrary-image' else image)
                return actual_readlink(path, *args, **kwargs)
            parent_samples = iter((500, 501)) if variant == 'parent-changed' else None
            with mock.patch.object(d, 'SUDO_ENTRYPOINTS', (str(entry),)), mock.patch.object(d.os, 'getuid', return_value=0), mock.patch.object(d.os, 'geteuid', return_value=0), mock.patch.object(d.os, 'getppid', side_effect=(lambda: next(parent_samples)) if parent_samples else lambda: 500), mock.patch.object(d.os, 'stat', side_effect=inspect), mock.patch.object(d.os, 'fstat', side_effect=lambda fd: metadata(actual_fstat(fd))), mock.patch.object(d.os, 'open', side_effect=opened), mock.patch.object(d.os, 'readlink', side_effect=link):
                return d.verified_invocation([], {'SUDO_UID': '1101'})

    def test_alternatives_chain_and_origin_negative_controls(self):
        self.assertEqual(self.invoke('valid'), 1101)
        for variant in ('arbitrary-image', 'inode-mismatch', 'writable-image', 'writable-parent',
                        'foreign-link', 'foreign-parent', 'parent-changed', 'loop'):
            with self.subTest(variant=variant), self.assertRaises(d.Refusal):
                self.invoke(variant)
