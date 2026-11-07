"""Finite cleanup costs and Git modes; process and identity boundaries are fake."""
import json
import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
import test_demo as fixtures
import test_publication as publication

d, p = fixtures.d, fixtures.p


class CompletionTests(unittest.TestCase):
    fixture = fixtures.StateTests.fixture
    setup_disk = publication.PublicationTests.setup_disk

    def release_case(self, mode, transition_cost, lease_cost):
        with self.setup_disk() as (r, s, b, root):
            gen = r['accounts'][0]['generation']
            memory_lock = s.locked
            final = False
            closes = []
            original_close = os.close

            @contextmanager
            def locked(name='transition.lock'):
                # Exercise the actual Store flock and descriptor close, with
                # synthetic ownership and the existing fake process backend.
                disk = d.Store.__new__(d.Store)
                disk.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    with disk.locked(name), memory_lock(name):
                        yield
                finally:
                    disk.close()

            def close(fd):
                path = os.readlink('/proc/self/fd/' + str(fd))
                original_close(fd)
                if final and path in (str(root / 'transition.lock'), str(root / (gen + '.stop.lock'))):
                    name = Path(path).name
                    cost = transition_cost if name == 'transition.lock' else lease_cost
                    b.now += cost
                    closes.append((name, cost))

            s.locked = locked
            bound = 110. if mode == 'launch' else 145. if mode == 'whole' else 105.
            first_kill = 100. if mode == 'kill' else None
            if mode == 'launch':
                spawn = b.spawn
                def near_bound(*args):
                    value = spawn(*args)
                    b.now = bound - .25
                    return value
                b.spawn = near_bound
            else:
                d.launch(r, 1101, fixtures.launch_request(), b'opaque', s, b, 100.)
                b.members.clear()
                rec = s.read(gen)
                rec['stop'] = dict(request=fixtures.stop_request(0),
                                   request_digest=d.digest(d.encoded(fixtures.stop_request(0))), started_at=d.utc(),
                                   started_mono=100., grace_seconds=0, kill_mono=first_kill,
                                   outcome='pending', events=[], signalled=0, killed=0,
                                   last_scan_complete=False, remaining=None,
                                   finished_at=None, elapsed_seconds=None)
                with s.locked():
                    s.write(gen, rec)
                b.now = bound - 2.5

            publications = []
            def published(value, write):
                nonlocal final
                if (value.get('stop') or {}).get('terminal_outcome'):
                    write()  # records the already observed, timely completion
                    return
                self.assertFalse(final, 'no follow-up correction write')
                write()
                candidate = value.get('launch_publication') if mode == 'launch' else value.get('stop', {}).get('completion_publication')
                if candidate:
                    publications.append(value)
                    b.now = bound - .25
                    final = True
            s.hook = published
            with mock.patch.object(d.os, 'close', side_effect=close):
                if mode == 'launch':
                    rec = d.launch(r, 1101, fixtures.launch_request(), b'opaque', s, b, 100.)
                else:
                    rec = d.stop(r, 1101, fixtures.stop_request(0), s, b, started=b.now)
            self.assertEqual(len(publications), 1)
            terminal = s.read(gen).get('stop') and s.read(gen)['stop'].get('terminal_outcome')
            self.assertEqual(len(closes), 1 if mode == 'launch' else 4 if terminal else 2)
            self.assertFalse(s.transition)
            self.assertFalse(s.leases)
            elapsed = rec['launch_elapsed_seconds'] if mode == 'launch' else rec['stop']['elapsed_seconds']
            response = d.response(mode, rec, mode == 'launch')
            self.assertAlmostEqual(elapsed, b.now - 100.)
            self.assertEqual(response['ok'], b.now < bound)
            durable = s.read(gen)
            if mode == 'launch':
                self.assertEqual(durable['launch_outcome'], 'unknown')
                self.assertIsNone(durable['launch_elapsed_seconds'])
                self.assertEqual(rec['launch_started_mono'], 100.)
            else:
                self.assertEqual(durable['stop']['outcome'], 'pending')
                self.assertIsNone(durable['stop']['elapsed_seconds'])
                self.assertIsNone(durable['stop']['finished_at'])
                self.assertEqual(rec['stop']['started_mono'], 100.)
                self.assertEqual(rec['stop']['kill_mono'], first_kill)
                self.assertEqual(rec['stop']['deadline_missed'], b.now >= 145.)
                self.assertEqual(rec['stop']['final_scan_deadline_missed'], first_kill is not None and b.now >= 105.)
            print(json.dumps(dict(case=mode, transition_cost=transition_cost, lease_cost=lease_cost,
                                  origin=100., first_kill=first_kill, bound=bound,
                                  completed=b.now, elapsed=elapsed, ok=response['ok'], closes=closes)))
            # Recovery must use the old clocks, with no corrective persistence,
            # census, signal, second attempt or optimistic durable success.
            final = False
            s.hook = lambda *args: self.fail('replay wrote state')
            b.on_scan = lambda *args: self.fail('replay scanned')
            calls = len(b.calls)
            b.now = bound + .5
            if mode == 'launch':
                replay = d.launch(r, 1101, fixtures.launch_request(), b'opaque', s, b, b.now)
            else:
                replay = d.stop(r, 1101, fixtures.stop_request(0), s, b, started=b.now)
            self.assertEqual(d.response(mode, replay, mode == 'launch')['ok'], bool(terminal))
            self.assertEqual(b.spawn_count, 1)
            self.assertEqual(len(b.calls), calls)

    def test_launch_transition_release_all_cutoff_neighbours(self):
        for cost in (0., .125, .25, .5):
            with self.subTest(cost=cost):
                self.release_case('launch', cost, 0.)

    def test_stop_both_locks_all_original_cutoff_neighbours(self):
        for mode in ('whole', 'kill'):
            for transition, lease in ((0., 0.), (.125, 0.), (.25, 0.), (.5, 0.),
                                      (0., .125), (0., .25), (0., .5), (.125, .125)):
                with self.subTest(mode=mode, transition=transition, lease=lease):
                    self.release_case(mode, transition, lease)


class GitModeTests(unittest.TestCase):
    def test_owner_execute_controls_git_binding_copy_and_digest(self):
        for frozen_exec in (False, True):
            for mode in (0o600, 0o645, 0o654, 0o655, 0o700, 0o755):
                for flag in ('assume-unchanged', 'skip-worktree'):
                    with self.subTest(frozen_exec=frozen_exec, mode=oct(mode), flag=flag), tempfile.TemporaryDirectory() as private:
                        root = Path(private, 'repo'); root.mkdir(mode=0o700)
                        home = Path(private, 'home'); home.mkdir(mode=0o700)
                        publication.FrozenTreeTests().fixture_tree(root)
                        target = root / 'README.md'
                        target.chmod(0o700 if frozen_exec else 0o600)
                        def git(*args):
                            result = p.command(['/usr/bin/git', '-C', str(root), *args], str(home))
                            self.assertEqual(result['exit'], 0, result)
                            return result['stdout'].strip()
                        git('init', '--template=', '--initial-branch=test')
                        git('config', 'core.filemode', 'true')
                        git('add', '.')
                        git('-c', 'user.name=Public Fixture', '-c', 'user.email=fixture@example.invalid',
                            '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture')
                        base = git('rev-parse', 'HEAD')
                        with mock.patch.object(p.demo, 'BASE', base):
                            baseline, _ = p.source_check(str(root), str(home))
                            expected = p.frozen_manifest(str(root), str(home))
                            target.chmod(mode)
                            actual_exec = bool(mode & stat.S_IXUSR)
                            summary = git('diff', '--summary')
                            self.assertEqual(bool(summary), frozen_exec != actual_exec)
                            if summary:
                                self.assertIn('mode change', summary)
                            git('update-index', '--' + flag, 'README.md')
                            self.assertEqual(git('status', '--porcelain=v1', '--untracked-files=all'), '')
                            destination = Path(private, 'copy'); destination.mkdir(mode=0o700)
                            # Unbound walk still uses the same owner bit for
                            # digest and normalized private copy permissions.
                            raw = p.manifest(str(root), p.time.monotonic() + 5, str(destination))
                            self.assertEqual(stat.S_IMODE((destination / 'README.md').stat().st_mode),
                                             0o700 if actual_exec else 0o600)
                            self.assertEqual(raw['digest'] == baseline['digest'], frozen_exec == actual_exec)
                            if frozen_exec == actual_exec:
                                checked, _ = p.source_check(str(root), str(home))
                                self.assertEqual(checked, baseline)
                            else:
                                with self.assertRaises(p.demo.Refusal):
                                    p.source_check(str(root), str(home))
                                bound_copy = Path(private, 'bound-copy'); bound_copy.mkdir(mode=0o700)
                                with self.assertRaises(p.demo.Refusal):
                                    p.manifest(str(root), p.time.monotonic() + 5, str(bound_copy), expected=expected)
                            print(json.dumps(dict(frozen_exec=frozen_exec, mode=oct(mode), flag=flag,
                                                  real_git_summary=summary, hidden_status='',
                                                  refused=frozen_exec != actual_exec)))
