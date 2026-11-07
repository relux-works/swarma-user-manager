"""Completion faults use real private Store files; process/identity boundaries fake."""
import copy
import errno
import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
import test_demo as fixtures
from test_demo import d, p, roster, launch_request, stop_request, MemoryStore, FakeRunner


class Interrupted(BaseException):
    pass


class PublicationTests(unittest.TestCase):
    fixture = fixtures.StateTests.fixture
    @contextmanager
    def setup_disk(self):
        with self.fixture() as (disk, root):
            r = roster()
            class DiskStore(MemoryStore):
                hook = None
                def read(self, gen):
                    return disk.read(gen)
                def write(self, gen, value):
                    super().write(gen, value)
                    if self.hook:
                        self.hook(value, lambda: disk.write(gen, value))
                    else:
                        disk.write(gen, value)
            store = DiskStore(r)
            disk.write('1' * 32, store.data['1' * 32])
            runner = FakeRunner(r, store)
            yield r, store, runner, root

    def reload(self, store, root):
        # Reopen an actual Store descriptor, rather than replaying an in-memory
        # copy. Ownership metadata remains the private fixture's synthetic root.
        reloaded = d.Store.__new__(d.Store)
        reloaded.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            return reloaded.read('1' * 32)
        finally:
            reloaded.close()

    def test_stop_fault_after_publication_both_original_cutoffs(self):
        for first_kill in (None, 100.0):
            for fault in ('crash', 'failed-followup'):
                with self.subTest(first_kill=first_kill, fault=fault), self.setup_disk() as (r, s, b, root):
                    d.launch(r, 1101, launch_request(), b'opaque', s, b, 100.)
                    b.members.clear()
                    b.on_scan = lambda _: (_ for _ in ()).throw(Interrupted())
                    with self.assertRaises(Interrupted):
                        d.stop(r, 1101, stop_request(0), s, b, started=100.)
                    b.on_scan = None
                    rec = s.read('1' * 32)
                    rec['stop']['kill_mono'] = first_kill
                    with s.locked():
                        s.write('1' * 32, rec)
                    bound = 145. if first_kill is None else 105.
                    b.now = bound - 2.1
                    publications = []
                    def faulted(value, write):
                        ev = value.get('stop')
                        candidate = ev and (ev.get('completion_publication') or ev['outcome'] == 'absent')
                        if publications:
                            raise OSError(errno.EIO, 'synthetic subsequent persistence failure')
                        if candidate:
                            write()
                            publications.append(copy.deepcopy(value))
                            b.now += .5
                            if fault == 'crash':
                                raise Interrupted('after durable publication')
                        else:
                            write()
                    s.hook = faulted
                    try:
                        result = d.stop(r, 1101, stop_request(0), s, b, started=b.now)
                        self.assertFalse(d.response('stop', result, False)['ok'])
                        self.assertAlmostEqual(result['stop']['elapsed_seconds'], bound + .4 - 100.)
                    except (Interrupted, OSError):
                        pass
                    self.assertEqual(len(publications), 1)
                    durable = self.reload(s, root)
                    print(json.dumps(dict(case='stop_publication', first_kill=first_kill, fault=fault, original_origin=100., original_bound=bound, now=b.now, durable_outcome=durable['stop']['outcome'], durable_elapsed=durable['stop']['elapsed_seconds'], publications=len(publications))))
                    self.assertEqual(durable['stop']['outcome'], 'pending')
                    self.assertIsNone(durable['stop']['finished_at'])
                    self.assertIsNone(durable['stop']['elapsed_seconds'])
                    self.assertEqual(durable['stop']['started_mono'], 100.)
                    self.assertEqual(durable['stop']['kill_mono'], first_kill)
                    # Retry must need neither a correction nor another write,
                    # census or signal. The failed persistence hook stays armed.
                    b.on_scan = lambda _: self.fail('replay initiated census')
                    before = len(b.calls)
                    replay = d.stop(r, 1101, stop_request(0), s, b, started=b.now)
                    self.assertEqual(len(b.calls), before)
                    self.assertFalse(d.response('stop', replay, False)['ok'])
                    self.assertEqual(replay['stop']['started_mono'], 100.)
                    self.assertEqual(replay['stop']['kill_mono'], first_kill)
                    self.assertTrue(replay['stop']['deadline_missed'] if first_kill is None else replay['stop']['final_scan_deadline_missed'])

    def test_launch_publication_cost_crash_reload_and_retry(self):
        for fault in ('none', 'crash', 'eio-after-durable'):
            with self.subTest(fault=fault), self.setup_disk() as (r, s, b, root):
                original_spawn = b.spawn
                def spawn(*args):
                    result = original_spawn(*args)
                    b.now = 109.75
                    return result
                b.spawn = spawn
                publications = []
                def slow(value, write):
                    candidate = value.get('launch_publication') or value['launch_outcome'] == 'receipt_seen'
                    write()
                    if candidate:
                        publications.append(copy.deepcopy(value))
                        b.now += .5
                        if fault == 'crash':
                            raise Interrupted('after durable publication')
                        if fault == 'eio-after-durable':
                            raise OSError(errno.EIO, 'synthetic directory-sync uncertainty')
                s.hook = slow
                try:
                    result = d.launch(r, 1101, launch_request(), b'opaque', s, b, 100.)
                    self.assertEqual(result['launch_elapsed_seconds'], 10.25)
                    self.assertFalse(d.response('launch', result, True)['ok'])
                except (Interrupted, OSError):
                    pass
                durable = self.reload(s, root)
                print(json.dumps(dict(case='launch_publication', fault=fault, original_origin=100., original_bound=110., now=b.now, durable_outcome=durable['launch_outcome'], durable_elapsed=durable['launch_elapsed_seconds'], publications=len(publications), spawn_count=b.spawn_count)))
                self.assertEqual(len(publications), 1)
                self.assertEqual(durable['launch_outcome'], 'unknown')
                self.assertIsNone(durable['launch_elapsed_seconds'])
                self.assertIsNotNone(durable['receipt'])
                self.assertEqual(durable['launch_started_mono'], 100.)
                s.hook = lambda *a: self.fail('replay wrote state')
                replay = d.launch(r, 1101, launch_request(), b'opaque', s, b, b.now)
                self.assertFalse(d.response('launch', replay, True)['ok'])
                self.assertEqual(b.spawn_count, 1)

    def test_timely_reply_requires_completed_publication_recovery_is_unconfirmed(self):
        with self.setup_disk() as (r, s, b, root):
            launched = d.launch(r, 1101, launch_request(), b'opaque', s, b, 100.)
            self.assertTrue(d.response('launch', launched, True)['ok'])
            self.assertEqual(self.reload(s, root)['launch_outcome'], 'unknown')
            b.members.clear()
            stopped = d.stop(r, 1101, stop_request(0), s, b, started=100.)
            self.assertTrue(d.response('stop', stopped, False)['ok'])
            self.assertEqual(stopped['stop']['elapsed_seconds'], 2.)
            self.assertEqual(self.reload(s, root)['stop']['outcome'], 'pending')
            replay = d.stop(r, 1101, stop_request(0), s, b)
            self.assertFalse(d.response('stop', replay, False)['ok'])


class FrozenTreeTests(unittest.TestCase):
    def fixture_tree(self, root):
        for path in d.COPY_EXCLUSIONS:
            link = root / path
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to('../../agents/skills/swarma-user-manager')
        (root / 'agents/skills/swarma-user-manager').mkdir(parents=True)
        (root / 'agents/skills/swarma-user-manager/SKILL.md').write_text('public fixture')
        (root / 'README.md').write_text('public baseline')
        (root / '.gitignore').write_text('.temp/\n')

    def test_immutable_objects_refuse_ignored_index_hidden_missing_mode_and_links(self):
        # Self-contained tiny Git tree exercises real immutable object commands.
        # The production BASE is substituted only for this synthetic fixture.
        for change in ('none', 'ignored', 'assume-unchanged', 'skip-worktree', 'missing', 'mode', 'empty-dir', 'third-link'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as private:
                root = Path(private, 'repo'); root.mkdir(mode=0o700)
                home = Path(private, 'home'); home.mkdir(mode=0o700)
                self.fixture_tree(root)
                def git(*args):
                    result = p.command(['/usr/bin/git', '-C', str(root), *args], str(home))
                    self.assertEqual(result['exit'], 0, result)
                    return result['stdout'].strip()
                git('init', '--template=', '--initial-branch=test')
                git('add', '.')
                git('-c', 'user.name=Public Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture')
                base = git('rev-parse', 'HEAD')
                target = root / 'README.md'
                if change == 'ignored':
                    (root / '.temp').mkdir(); (root / '.temp/extra').write_text('extra')
                elif change in ('assume-unchanged', 'skip-worktree'):
                    git('update-index', '--' + change, 'README.md'); target.write_text('changed')
                    self.assertEqual(git('status', '--porcelain=v1', '--untracked-files=all'), '')
                elif change == 'missing':
                    target.unlink()
                elif change == 'mode':
                    target.chmod(0o755)
                elif change == 'empty-dir':
                    (root / 'extra-empty').mkdir()
                elif change == 'third-link':
                    (root / 'third').symlink_to('README.md')
                with mock.patch.object(p.demo, 'BASE', base):
                    if change == 'none':
                        copied, _ = p.source_check(str(root), str(home))
                        destination = Path(private, 'copy'); destination.mkdir(mode=0o700)
                        options = {'expected': p.frozen_manifest(str(root), str(home))} if hasattr(p, 'frozen_manifest') else {}
                        actual = p.manifest(str(root), p.time.monotonic() + 5, str(destination), **options)
                        self.assertEqual(actual, copied)
                        self.assertTrue((destination / 'agents/skills/swarma-user-manager/SKILL.md').is_file())
                    else:
                        with self.assertRaises(p.demo.Refusal):
                            p.source_check(str(root), str(home))

    def test_post_preflight_mutation_cannot_copy_under_frozen_manifest(self):
        with tempfile.TemporaryDirectory() as private:
            root = Path(private, 'repo'); root.mkdir(mode=0o700)
            self.fixture_tree(root)
            p.command(['/usr/bin/git', 'init', '--template=', str(root)], private)
            p.command(['/usr/bin/git', '-C', str(root), 'add', '.'], private)
            p.command(['/usr/bin/git', '-C', str(root), '-c', 'user.name=Public Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture'], private)
            base = p.command(['/usr/bin/git', '-C', str(root), 'rev-parse', 'HEAD'], private)['stdout'].strip()
            with mock.patch.object(p.demo, 'BASE', base):
                options = {'expected': p.frozen_manifest(str(root), private)} if hasattr(p, 'frozen_manifest') else {}
                p.source_check(str(root), private)
                (root / 'README.md').write_text('changed after preflight')
                destination = Path(private, 'copy'); destination.mkdir(mode=0o700)
                with self.assertRaises(p.demo.Refusal):
                    p.manifest(str(root), p.time.monotonic() + 5, str(destination), **options)
