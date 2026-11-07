"""Offline models and unprivileged Linux primitives; no UID/root/VM qualification."""
import base64
import copy
import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

DEMO_DIR = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


d = load('demo_under_test', DEMO_DIR / 'swarma_demo.py')
p = load('provision_under_test', DEMO_DIR / 'provision.py')


def roster():
    # Synthetic test pins only: never an admission for a real machine or caller.
    return {'format': 'swarma-user-manager demo-roster/1', 'source_revision': d.BASE,
            'boot_id': '11111111-1111-1111-1111-111111111111',
            'operator': {'name': 'swarma-operator', 'uid': 1901},
            'dispatcher': {'name': 'fixture-dispatcher', 'uid': 1900, 'gid': 1900,
                           'principal': 'fixture-dispatcher', 'generation': 'f' * 32},
            'executor': {'id': d.EXECUTOR_ID, 'path': d.EXECUTOR, 'sha256': 'a' * 64},
            'runtime': {'admitted': True, 'inventory_qualified': True,
                        'creation_exclusion_qualified': True, 'interpreter_qualified': True},
            'accounts': [{'name': name, 'uid': 30000 + i, 'gid': 30000 + i,
                          'generation': str(i + 1) * 32, 'owning_dispatcher': 'fixture-dispatcher',
                          'home': '/srv/swarma-demo/home/' + name,
                          'workspace': '/srv/swarma-demo/work/' + name,
                          'copy_digest': 'b' * 64} for i, name in enumerate(d.NAMES)]}


def launch_request(plan=b'opaque\x00\xff'):
    return {'v': 1, 'op': 'launch.start', 'request_id': 'launch-effect', 'generation': '1' * 32,
            'execution_id': 'EX-fixture', 'epoch': 3, 'executor': d.EXECUTOR_ID,
            'plan': base64.b64encode(plan).decode()}


def stop_request(grace=10):
    args = {'generation': '1' * 32, 'execution_id': 'EX-fixture'}
    if grace is not None:
        args['grace_seconds'] = grace
    return {'v': 1, 'op': 'exec.stop', 'request_id': 'stop-effect', 'args': args}


class MemoryStore:
    def __init__(self, r):
        row = r['accounts'][0]
        self.data = {row['generation']: {'format': 'swarma-user-manager demo-reservation/1',
                                       'account': row, 'dispatcher': r['dispatcher'], 'boot_id': r['boot_id']}}
        self.transition = False
        self.leases = set()
        self.writes = []
        self.receipts = []

    @contextmanager
    def locked(self, name='transition.lock'):
        if name in self.leases:
            d.refuse('state_conflict')
        self.leases.add(name)
        if name == 'transition.lock':
            self.transition = True
        try:
            yield
        finally:
            self.leases.remove(name)
            if name == 'transition.lock':
                self.transition = False

    def read(self, gen):
        if gen not in self.data:
            raise FileNotFoundError
        return copy.deepcopy(self.data[gen])

    def write(self, gen, value):
        if not self.transition:
            raise AssertionError('state write outside transition exclusion')
        self.data[gen] = copy.deepcopy(value)
        self.writes.append(copy.deepcopy(value))

    def receipt(self, gen, execution, receipt):
        if not self.transition or self.data[gen].get('receipt') is not None:
            raise AssertionError('receipt not before drop under exclusion')
        self.receipts.append(copy.deepcopy(receipt))


class FakeRunner:
    def __init__(self, r, store):
        self.roster = r
        self.store = store
        self.now = 100.0
        self.members = []
        self.complete = True
        self.survive_term = False
        self.survive_kill = False
        self.spawn_count = 0
        self.calls = []
        self.match = True
        self.lost = False
        self.spawn_error = None
        self.on_scan = None
        self.on_signal = None

    def clock(self):
        return self.now

    def sleep(self, seconds):
        if self.store.transition:
            raise AssertionError('transition lock held across wait')
        self.now += seconds

    def check(self, row):
        if row != self.roster['accounts'][0]:
            d.refuse('target_not_owned')

    def launch_check(self, row, deadline):
        self.check(row)
        if self.now >= deadline:
            d.refuse('request_timeout')

    def scan(self, row, deadline):
        if self.on_scan:
            self.on_scan(self)
        return list(self.members), self.complete

    def receipt_matches(self, row, receipt):
        return self.match

    def spawn(self, row, request, plan, persist, deadline):
        if not self.store.transition or self.store.data[row['generation']].get('format') != 'swarma-user-manager demo-attempt/1':
            raise AssertionError('no irreversible intent before physical start')
        self.spawn_count += 1
        receipt = {'execution_id': request['execution_id'], 'epoch': request['epoch'],
                   'pid': 42, 'start_time': 900, 'boot_id': self.roster['boot_id'], 'session_id': 42}
        persist(receipt)
        self.members = [d.Process(42, 900, 42, (row['uid'],) * 4, (row['gid'],) * 4)]
        if self.spawn_error:
            raise self.spawn_error
        if self.lost:
            self.now = deadline + 0.01
            return 'unknown'
        return 'receipt_seen'

    def signal(self, row, member, number):
        if self.store.transition:
            raise AssertionError('transition lock held over signal')
        if number == signal.SIGKILL and self.store.data[row['generation']]['stop']['kill_mono'] is None:
            raise AssertionError('KILL before durable original bound')
        self.calls.append((self.now, member, number))
        if self.on_signal:
            return self.on_signal(self, member, number)
        if (number == signal.SIGTERM and not self.survive_term) or (number == signal.SIGKILL and not self.survive_kill):
            self.members = [p for p in self.members if p != member]
        return 'sent'


class BoundaryTests(unittest.TestCase):
    def assert_refusal(self, code, call, *args):
        with self.assertRaises(d.Refusal) as exc:
            call(*args)
        self.assertEqual(exc.exception.code, code)

    def test_exact_closed_launch_and_opaque_maximum_plan(self):
        plan = bytes(range(256)) * 192
        request, decoded = d.decode(d.encoded(launch_request(plan)), True)
        self.assertEqual(len(decoded), 48 * 1024)
        self.assertEqual(decoded, plan)
        self.assertEqual(request['epoch'], 3)
        self.assert_refusal('request_too_large', d.decode, d.encoded(launch_request(plan + b'x')), True)

    def test_duplicate_nested_unknown_trailing_and_wrong_types(self):
        good = d.encoded(launch_request())
        for data in (good.replace(b'"epoch":3', b'"epoch":3,"epoch":4'), good + b'{}', b'null', b'[]', good.replace(b'"epoch":3', b'"epoch":true'), good.replace(b'"v":1', b'"v":1.0')):
            self.assert_refusal('request_invalid', d.decode, data, True)
        bad = launch_request()
        bad['uid'] = 30000
        self.assert_refusal('request_invalid', d.decode, d.encoded(bad), True)
        data = d.encoded(stop_request()).replace(b'"grace_seconds":10', b'"grace_seconds":10,"grace_seconds":20')
        self.assert_refusal('request_invalid', d.decode, data, False)

    def test_bounded_ids_generation_epoch_and_canonical_base64(self):
        for key, value in (('request_id', 'x' * 65), ('generation', '0' * 32), ('generation', 'A' * 32), ('execution_id', '../escape'), ('epoch', 0), ('epoch', 2**53), ('plan', 'Zh=='), ('plan', 'Zg==\n')):
            obj = launch_request()
            obj[key] = value
            self.assert_refusal('request_invalid', d.decode, d.encoded(obj), True)
        self.assert_refusal('executor_not_approved', d.decode, d.encoded(dict(launch_request(), executor='curator-run')), True)

    def test_dispatcher_stop_only_no_create_retire_or_observe(self):
        for op in ('user.create', 'user.retire', 'user.bump', 'effect.observe', 'anything'):
            obj = stop_request()
            obj['op'] = op
            self.assert_refusal('caller_role_not_permitted', d.decode, d.encoded(obj), False)
        self.assertEqual(d.decode(d.encoded(stop_request(None)), False)[0]['args'].get('grace_seconds', 10), 10)
        for value in (-1, 31, True, 1.0, '10'):
            self.assert_refusal('request_invalid', d.decode, d.encoded(stop_request(value)), False)
        for value in (0, 30):
            d.decode(d.encoded(stop_request(value)), False)

    def test_intake_refuses_cap_and_exhausted_original_time(self):
        r, w = os.pipe()
        try:
            os.write(w, b'x' * 64)
            os.close(w)
            self.assert_refusal('request_too_large', d.intake, r, 63, time.monotonic())
        finally:
            os.close(r)
        r, w = os.pipe()
        try:
            os.write(w, b'{}')
            self.assert_refusal('request_timeout', d.intake, r, 16, time.monotonic() - 6)
        finally:
            os.close(r)
            os.close(w)

    def test_intake_positive_and_no_secrets_environment(self):
        r, w = os.pipe()
        os.write(w, b'{}')
        os.close(w)
        try:
            self.assertEqual(d.intake(r, 16, time.monotonic()), b'{}')
        finally:
            os.close(r)
        self.assertNotIn('SSH_AUTH_SOCK', os.environ)
        self.assertNotIn('DBUS_SESSION_BUS_ADDRESS', os.environ)
        self.assertTrue(os.path.isabs(os.environ['HOME']))
        self.assertEqual(stat.S_IMODE(os.stat(os.environ['HOME']).st_mode), 0o700)
        self.assertFalse(Path('/home').exists())
        self.assertFalse(Path('/run/user').exists())
        with self.assertRaises(OSError):
            (DEMO_DIR / 'forbidden-write').write_text('must refuse readonly source')

    def test_roster_inclusive_range_equal_ids_and_unique_generation(self):
        r = roster()
        r['accounts'][2]['uid'] = r['accounts'][2]['gid'] = 30019
        self.assertEqual(d.validate_roster(r), r)
        for uid, gid in ((29999, 29999), (30020, 30020), (30000, 30001), (True, True)):
            bad = roster()
            bad['accounts'][0].update(uid=uid, gid=gid)
            self.assert_refusal('state_unavailable', d.validate_roster, bad)
        bad = roster()
        bad['accounts'][1]['generation'] = bad['accounts'][0]['generation']
        self.assert_refusal('target_not_owned', d.validate_roster, bad)
        bad = roster()
        bad['accounts'][0]['owning_dispatcher'] = 'foreign'
        self.assert_refusal('target_not_owned', d.validate_roster, bad)

    def test_roster_pins_have_no_live_defaults_or_caller_paths(self):
        for field in ('uid', 'principal', 'generation', 'name'):
            bad = roster()
            del bad['dispatcher'][field]
            self.assert_refusal('request_invalid', d.validate_roster, bad)
        for key, value in (('home', '/tmp/foreign'), ('workspace', '/tmp/foreign'), ('uid', 1900), ('copy_digest', '')):
            bad = roster()
            bad['accounts'][0][key] = value
            self.assert_refusal('state_unavailable', d.validate_roster, bad)
        bad = roster()
        bad['operator']['name'] = 'interactive-person'
        self.assert_refusal('state_unavailable', d.validate_roster, bad)
        for uid in (1901, 30000, 0, 1902):
            self.assert_refusal('caller_role_not_permitted', d.authorize, roster(), uid)
        self.assertEqual(d.authorize(roster(), 1900), roster()['dispatcher'])

    def test_invocation_refuses_args_nonroot_and_forged_sudo(self):
        self.assert_refusal('argv_not_allowed', d.verified_invocation, ['--uid=30000'], {})
        self.assert_refusal('not_root', d.verified_invocation, [], {'SUDO_UID': '1900'})
        with mock.patch.object(d.os, 'getuid', return_value=0), mock.patch.object(d.os, 'geteuid', return_value=0):
            for value in ('', '-1', '0', '4294967295', '1x', '\u0661'):
                self.assert_refusal('not_invoked_by_sudo', d.verified_invocation, [], {'SUDO_UID': value})
            self.assert_refusal('not_invoked_by_sudo', d.verified_invocation, [], {'SUDO_UID': '1900'})
    def test_synthetic_verified_sudo_parent_identity_positive_and_inode_mismatch(self):
        # No sudo execution: trusted-parent metadata is synthetic, descriptor
        # identity comparison is real and binds the exact opened file.
        with tempfile.TemporaryDirectory() as root:
            expected = Path(root, 'expected')
            other = Path(root, 'other')
            expected.write_bytes(b'fixture')
            other.write_bytes(b'fixture')
            original_open, original_stat = os.open, os.fstat
            actual_target = [expected]
            def fixture_open(path, flags, *args, **kwargs):
                if path == '/proc/500/exe':
                    return original_open(actual_target[0], os.O_RDONLY | os.O_CLOEXEC)
                return original_open(path, flags, *args, **kwargs)
            def fixture_fstat(fd):
                st = original_stat(fd)
                return types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o4755,
                                             st_dev=st.st_dev, st_ino=st.st_ino, st_nlink=1)
            with mock.patch.object(d.os, 'getuid', return_value=0), mock.patch.object(d.os, 'geteuid', return_value=0), mock.patch.object(d.os, 'getppid', return_value=500), mock.patch.object(d.os, 'readlink', return_value='/usr/bin/sudo'), mock.patch.object(d.os, 'stat', return_value=types.SimpleNamespace(st_uid=0)), mock.patch.object(d, 'protected', side_effect=lambda _: original_open(expected, os.O_RDONLY | os.O_CLOEXEC)), mock.patch.object(d.os, 'open', side_effect=fixture_open), mock.patch.object(d.os, 'fstat', side_effect=fixture_fstat):
                self.assertEqual(d.verified_invocation([], {'SUDO_UID': '1900'}), 1900)
                actual_target[0] = other
                self.assert_refusal('not_invoked_by_sudo', d.verified_invocation, [], {'SUDO_UID': '1900'})



class AttemptTests(unittest.TestCase):
    assert_refusal = BoundaryTests.assert_refusal
    def setUp(self):
        self.r = roster()
        self.store = MemoryStore(self.r)
        self.runner = FakeRunner(self.r, self.store)

    def start(self):
        return d.launch(self.r, 1900, launch_request(), b'opaque\x00\xff', self.store, self.runner, self.runner.clock())

    def end(self, grace=10):
        return d.stop(self.r, 1900, stop_request(grace), self.store, self.runner)

    def test_positive_one_start_receipt_before_drop_and_terminal_replay(self):
        rec = self.start()
        self.assertEqual(rec['launch_outcome'], 'receipt_seen')
        self.assertEqual(len(self.store.receipts), 1)
        self.assertEqual(self.start()['receipt'], rec['receipt'])
        self.assertEqual(self.runner.spawn_count, 1)
        result = self.end()
        self.assertEqual(result['stop']['outcome'], 'absent')
        self.assertGreaterEqual(result['stop']['elapsed_seconds'], d.QUIET)
        self.assertLess(result['stop']['elapsed_seconds'], d.STOP_WHOLE)
        calls = len(self.runner.calls)
        self.runner.match = False
        self.end()
        self.assertEqual(len(self.runner.calls), calls)

    def test_lost_reply_never_refills_receipt_deadline_or_restarts(self):
        self.runner.lost = True
        result = self.start()
        self.assertEqual(result['launch_outcome'], 'unknown')
        self.assertGreater(result['launch_elapsed_seconds'], 10)
        self.assertIsNotNone(result['receipt'])
        self.start()
        self.assertEqual(self.runner.spawn_count, 1)
        self.assertFalse(d.response('launch-effect', result, True)['ok'])
        self.assertEqual(self.end()['stop']['outcome'], 'absent')

    def test_precreated_reservation_required_missing_state_is_not_permission(self):
        self.store.data.clear()
        self.assert_refusal('state_unavailable', self.start)
        self.assertEqual(self.runner.spawn_count, 0)

    def test_new_execution_epoch_or_request_id_cannot_bypass_one_attempt(self):
        self.start()
        for key, value in (('execution_id', 'EX-second'), ('epoch', 4), ('request_id', 'second-effect'), ('plan', base64.b64encode(b'changed').decode())):
            request = launch_request()
            request[key] = value
            self.assert_refusal('execution_already_started', d.launch, self.r, 1900, request, b'changed', self.store, self.runner, self.runner.clock())
        self.assertEqual(self.runner.spawn_count, 1)

    def test_dirty_or_partial_census_prevents_physical_launch(self):
        self.runner.complete = False
        self.assert_refusal('uid_not_clean', self.start)
        self.runner.complete = True
        self.runner.members = [d.Process(40, 1, 40, (30000,) * 4, (30000,) * 4)]
        self.assert_refusal('uid_not_clean', self.start)
        self.assertEqual(self.runner.spawn_count, 0)

    def test_drop_or_exec_failure_retains_original_attempt_and_receipt(self):
        self.runner.spawn_error = d.Refusal('privilege_drop_failed')
        result = self.start()
        self.assertEqual(result['launch_outcome'], 'unknown')
        self.assertEqual(result['launch_failure'], 'privilege_drop_failed')
        self.assertIsNotNone(result['receipt'])
        self.start()
        self.assertEqual(self.runner.spawn_count, 1)

    def test_detached_and_pre_receipt_children_are_uid_scope_not_session_scope(self):
        self.start()
        self.runner.members.extend([d.Process(43, 10, 999, (30000,) * 4, (30000,) * 4), d.Process(44, 5, 444, (30000,) * 4, (30000,) * 4)])
        self.runner.members = self.runner.members[1:]  # root has already exited
        result = self.end()
        self.assertEqual(result['stop']['outcome'], 'absent')
        self.assertEqual({call[1].pid for call in self.runner.calls}, {43, 44})

    def test_pid_reuse_refuses_signals_and_retains_pending(self):
        self.start()
        self.runner.match = False
        result = self.end()
        self.assertEqual(result['stop']['outcome'], 'pending')
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(result['stop']['events'][0]['failure'], 'receipt_identity_changed')

    def test_signal_race_or_permission_error_does_not_prove_absence(self):
        self.start()
        self.runner.on_signal = lambda runner, member, number: 'identity_changed'
        self.runner.survive_term = self.runner.survive_kill = True
        result = self.end(grace=0)
        self.assertEqual(result['stop']['outcome'], 'pending')
        self.assertLessEqual(result['stop']['elapsed_seconds'], 5.01)
        self.assertTrue(any(signal['outcome'] == 'identity_changed' for event in result['stop']['events'] for signal in event.get('signals', [])))

    def test_term_then_kill_maximum_grace_and_five_second_final_scan(self):
        self.start()
        self.runner.survive_term = True
        result = self.end(grace=30)
        term = next(call for call in self.runner.calls if call[2] == signal.SIGTERM)
        kill = next(call for call in self.runner.calls if call[2] == signal.SIGKILL)
        self.assertEqual(kill[0] - term[0], 30)
        self.assertEqual(result['stop']['outcome'], 'absent')
        self.assertLessEqual(result['stop']['elapsed_seconds'], 35)
        self.assertGreaterEqual(result['stop']['elapsed_seconds'], 32)

    def test_unkillable_remains_pending_no_success_wire_receipt(self):
        self.start()
        self.runner.survive_term = self.runner.survive_kill = True
        result = self.end()
        self.assertEqual(result['stop']['outcome'], 'pending')
        self.assertEqual(result['stop']['remaining'], 1)
        self.assertLessEqual(result['stop']['elapsed_seconds'], 15.01)
        self.assertFalse(d.response('stop-effect', result, False)['ok'])

    def test_partial_scan_empty_never_establishes_absence(self):
        self.start()
        self.runner.members.clear()
        self.runner.complete = False
        result = self.end()
        self.assertEqual(result['stop']['outcome'], 'pending')
        self.assertIsNone(result['stop']['remaining'])
        self.assertAlmostEqual(result['stop']['elapsed_seconds'], 45, delta=0.001)

    def test_quiet_reappearance_resets_window_without_resetting_deadlines(self):
        self.start()
        self.runner.members.clear()
        appeared = []
        def on_scan(runner):
            if not appeared and runner.now >= 101:
                appeared.append(runner.now)
                runner.members = [d.Process(99, 1, 99, (30000,) * 4, (30000,) * 4)]
        self.runner.on_scan = on_scan
        result = self.end()
        self.assertEqual(result['stop']['outcome'], 'absent')
        self.assertGreaterEqual(result['stop']['elapsed_seconds'], 3)
        self.assertEqual(result['stop']['started_mono'], 100)
        self.assertEqual(self.runner.calls[-1][1].pid, 99)

    def test_continuation_cannot_refill_grace_or_kill_or_whole_budget(self):
        self.start()
        self.runner.survive_term = self.runner.survive_kill = True
        first = self.end()
        origin = first['stop']['started_mono']
        kill = first['stop']['kill_mono']
        self.runner.now += 60
        again = self.end()
        self.assertEqual(again['stop']['started_mono'], origin)
        self.assertEqual(again['stop']['kill_mono'], kill)
        self.assertEqual(again['stop']['outcome'], 'pending')
        self.assertTrue(again['stop']['deadline_missed'])
        self.assertTrue(again['stop']['events'][-1]['late_narrowing'])
        self.assertEqual(self.runner.calls[-1][2], signal.SIGKILL)
        self.assertEqual(self.runner.calls[-1][0], self.runner.now)
        self.assert_refusal('request_id_conflict', self.end, 20)

    def test_missing_receipt_wrong_generation_latest_receipt_and_caller(self):
        self.start()
        self.assert_refusal('caller_role_not_permitted', d.stop, self.r, 1901, stop_request(), self.store, self.runner)
        request = stop_request()
        request['args']['execution_id'] = 'EX-old'
        self.assert_refusal('state_conflict', d.stop, self.r, 1900, request, self.store, self.runner)
        self.store.data['1' * 32]['receipt'] = None
        self.assert_refusal('state_conflict', self.end)
        self.assertEqual(self.runner.calls, [])

    def test_stop_intake_time_is_in_original_whole_budget(self):
        self.start()
        self.runner.members.clear()
        self.runner.complete = False
        self.runner.now += 5
        result = d.stop(self.r, 1900, stop_request(), self.store, self.runner, started=100)
        self.assertEqual(result['stop']['started_mono'], 100)
        self.assertAlmostEqual(self.runner.now, 145)


class PrimitiveTests(unittest.TestCase):
    def test_sealed_maximum_plan_is_readonly_and_cannot_be_changed(self):
        import fcntl
        data = bytes(range(256)) * 192
        fd = d.sealed_plan(data)
        try:
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            self.assertEqual(os.read(fd, len(data) + 1), data)
            with self.assertRaises(OSError):
                os.write(fd, b'overwrite')
            with self.assertRaises(OSError):
                os.ftruncate(fd, 0)
            alias = os.open('/proc/self/fd/' + str(fd), os.O_WRONLY)
            try:
                with self.assertRaises(OSError):
                    os.write(alias, b'overwrite')
            finally:
                os.close(alias)
        finally:
            os.close(fd)

    def test_both_output_streams_cap_at_one_mib_and_continue_draining(self):
        with tempfile.TemporaryDirectory() as workspace:
            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()
            child = os.fork()
            if child == 0:
                try:
                    os.close(out_w)
                    os.close(err_w)
                    d.drain({out_r: 'stdout.log', err_r: 'stderr.log'}, workspace)
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            os.close(out_r)
            os.close(err_r)
            try:
                # More than pipe capacity beyond each retention limit. The
                # writer can finish only if the excess is actually drained.
                for fd, char in ((out_w, b'O'), (err_w, b'E')):
                    for _ in range(40):
                        view = memoryview(char * 65536)
                        while view:
                            view = view[os.write(fd, view):]
                    os.close(fd)
                _, status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                for name, char in (('stdout.log', b'O'), ('stderr.log', b'E')):
                    body = Path(workspace, name).read_bytes()
                    self.assertEqual(body, char * d.OUTPUT_MAX)
                    self.assertEqual(stat.S_IMODE(Path(workspace, name).stat().st_mode), 0o600)
            finally:
                for fd in (out_w, err_w):
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def test_fixed_executor_refuses_unprivileged_uid_without_witness(self):
        exe = os.environ.get('DEMO_TEST_EXECUTOR')
        self.assertIsNotNone(exe)
        result = subprocess.run([exe], env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 71)
        self.assertEqual(result.stdout + result.stderr, b'')

    def test_native_pidfd_signal_revalidates_incarnation_before_signal(self):
        row = roster()['accounts'][0]
        native = d.Native(roster())
        native.check = lambda _: None
        old = d.Process(42, 1, 42, (30000,) * 4, (30000,) * 4)
        changed = d.Process(42, 2, 42, (30000,) * 4, (30000,) * 4)
        with mock.patch.object(d.os, 'pidfd_open', return_value=99), mock.patch.object(d, 'process', return_value=changed), mock.patch.object(d.os, 'close') as close, mock.patch.object(d.signal, 'pidfd_send_signal') as send:
            self.assertEqual(native.signal(row, old, signal.SIGKILL), 'identity_changed')
            send.assert_not_called()
            close.assert_called_once_with(99)
        with mock.patch.object(d.os, 'pidfd_open', return_value=99), mock.patch.object(d, 'process', return_value=old), mock.patch.object(d.os, 'close'), mock.patch.object(d.signal, 'pidfd_send_signal') as send:
            self.assertEqual(native.signal(row, old, signal.SIGKILL), 'sent')
            send.assert_called_once_with(99, signal.SIGKILL, None, 0)

    def run_unprivileged_pipeline(self, exe, valid):
        # Real fork/session/barriers/FD3/fexecve/drainer; root ownership and drop
        # are synthetic. This is explicitly not a successful privileged launch.
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as workspace:
            r = roster()
            row = dict(r['accounts'][0], uid=os.getuid(), gid=os.getgid(), home=home, workspace=workspace)
            r['executor']['sha256'] = d.digest(exe.read_bytes())
            backend = d.Native(r)
            actual_process = d.process
            calls = []
            def fixture_process(pid):
                real = actual_process(pid)
                calls.append(pid)
                return d.Process(pid, real.start_time, real.session_id, (0,) * 4 if len(calls) == 1 else (os.getuid(),) * 4,
                                 (0,) * 4 if len(calls) == 1 else (os.getgid(),) * 4)
            def fixture_open(path, **kwargs):
                if path == d.EXECUTOR:
                    return os.open(exe, os.O_RDONLY | os.O_CLOEXEC)
                if path == home:
                    return os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                raise AssertionError('unexpected fixture path')
            receipts = []
            with mock.patch.object(d, 'protected', side_effect=fixture_open), mock.patch.object(d, 'process', side_effect=fixture_process), mock.patch.object(d, 'drop', return_value=None):
                if valid:
                    outcome = d.spawn(backend, row, launch_request(bytes(range(256)) * 192), bytes(range(256)) * 192, lambda value: receipts.append(value), time.monotonic() + 5)
                    self.assertEqual(outcome, 'receipt_seen')
                else:
                    with self.assertRaises(d.NativeFailure) as exc:
                        d.spawn(backend, row, launch_request(bytes(range(256)) * 192), bytes(range(256)) * 192, lambda value: receipts.append(value), time.monotonic() + 5)
                    self.assertEqual(exc.exception.detail, {'stage': 'exec', 'type': 'OSError', 'errno': 8})
            self.assertEqual(len(receipts), 1)
            try:
                pid, status = os.waitpid(receipts[0]['pid'], 0)
                self.assertEqual(pid, receipts[0]['pid'])
                code = os.waitstatus_to_exitcode(status)
            except ChildProcessError:
                facts = [e for e in backend.launch_evidence if e['stage'] == 'child_exit_observed']
                self.assertEqual(len(facts), 1)
                code = facts[0]['exit']
            self.assertEqual(code, 0 if valid else 127)
            if not valid:
                return
            end = time.monotonic() + 3
            while time.monotonic() < end:
                path = Path(workspace, 'stdout.log')
                if path.exists() and path.stat().st_size:
                    break
                time.sleep(0.01)
            fact = json.loads(path.read_text())
            self.assertEqual(fact['plan_bytes'], d.PLAN_MAX)
            self.assertEqual(fact['inherited_fds'], [0, 1, 2, 3])
            self.assertEqual(fact['scope'], 'unprivileged fixture')
            self.assertEqual(Path(workspace, 'stderr.log').read_bytes(), b'')

    def test_unprivileged_native_fd_pipeline_with_synthetic_root_stage(self):
        self.run_unprivileged_pipeline(Path('/private/bin/fd-probe'), True)

    def test_real_exec_failure_keeps_receipt_and_transmits_errno_after_fd_scrub(self):
        with tempfile.TemporaryDirectory() as private:
            exe = Path(private, 'invalid-elf')
            exe.write_bytes(b'\x7fELF' + b'not executable' * 16)
            exe.chmod(0o700)
            self.run_unprivileged_pipeline(exe, False)

    def test_root_protected_regular_positive_and_link_refusal(self):
        # User namespaces map host root to the overflow UID. Simulate only
        # root ownership; all opens/no-follow/type/mode/ACL checks are real.
        actual_fstat = os.fstat
        def fixture_ownership(fd):
            info = actual_fstat(fd)
            return types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)
        with mock.patch.object(d.os, 'fstat', side_effect=fixture_ownership):
            fd = d.protected('/usr/bin/python3.14', mode=0o755)
            os.close(fd)
            with self.assertRaises(OSError):
                d.protected('/usr/bin/python3', mode=0o755)  # actual no-follow link


class StateTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        # Root ownership is synthetic; atomic/no-follow/flock/fsync behavior is
        # exercised on a private unprivileged filesystem, not a host root path.
        with tempfile.TemporaryDirectory() as root:
            state = d.Store.__new__(d.Store)
            state.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            actual_fstat = os.fstat
            def ownership(fd):
                info = actual_fstat(fd)
                return types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode,
                                             st_nlink=info.st_nlink)
            with mock.patch.object(d.os, 'fstat', side_effect=ownership):
                try:
                    yield state, Path(root)
                finally:
                    state.close()

    def test_real_state_lock_and_atomic_record_publication(self):
        with self.fixture() as (store, root):
            gen = '1' * 32
            with store.locked():
                store.write(gen, {'original': 'preserved'})
                self.assertEqual(store.read(gen), {'original': 'preserved'})
                with self.assertRaises(d.Refusal) as exc:
                    with store.locked():
                        self.fail('same transition was concurrently acquired')
                self.assertEqual(exc.exception.code, 'state_conflict')
                with store.locked(gen + '.stop.lock'):
                    pass
            self.assertFalse((root / (gen + '.new')).exists())
            self.assertEqual(stat.S_IMODE((root / (gen + '.json')).stat().st_mode), 0o600)
            (root / (gen + '.json')).unlink()
            (root / 'outside').write_text('{"must":"not read"}')
            (root / (gen + '.json')).symlink_to('outside')
            with self.assertRaises(OSError):
                store.read(gen)

    def test_atomic_receipt_and_crash_temporary_never_overwrite_original(self):
        with self.fixture() as (store, root):
            gen = '1' * 32
            receipts = root / 'receipts'
            receipts.mkdir(mode=0o700)
            def opened(path, **kwargs):
                self.assertEqual(path, d.STATE + '/receipts/' + gen)
                return os.open(receipts, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            receipt = dict(execution_id='EX-fixture', epoch=3, pid=42, start_time=900,
                           boot_id=roster()['boot_id'], session_id=42)
            with mock.patch.object(d, 'protected', side_effect=opened):
                store.receipt(gen, 'EX-fixture', receipt)
                self.assertEqual(json.loads((receipts / 'EX-fixture.json').read_bytes()), receipt)
                self.assertEqual(stat.S_IMODE((receipts / 'EX-fixture.json').stat().st_mode), 0o644)
                self.assertFalse((receipts / 'EX-fixture.new').exists())
                with self.assertRaises(d.Refusal):
                    store.receipt(gen, 'EX-fixture', dict(receipt, epoch=4))
                with mock.patch.object(d.os, 'fsync', side_effect=OSError(5, 'synthetic IO failure')):
                    with self.assertRaises(OSError):
                        store.receipt(gen, 'EX-interrupted', receipt)
                self.assertFalse((receipts / 'EX-interrupted.json').exists())
                self.assertTrue((receipts / 'EX-interrupted.new').exists())
                with self.assertRaises(FileExistsError):
                    store.receipt(gen, 'EX-interrupted', receipt)
                self.assertEqual(json.loads((receipts / 'EX-fixture.json').read_bytes()), receipt)


class OperatorTests(unittest.TestCase):
    def test_recorded_preflight_positive_has_no_account_effect(self):
        with tempfile.TemporaryDirectory() as private:
            admission, record = Path(private, 'admission.json'), Path(private, 'record.json')
            r = roster()
            r['runtime'] = dict.fromkeys(r['runtime'], False)
            admission.write_bytes(d.encoded(r))
            with mock.patch.object(p.sys, 'argv', ['provision.py', '--admission', str(admission), '--source', '/source', '--record', str(record)]), mock.patch.object(p, 'source_check', return_value=({'digest': 'b' * 64, 'entries': 1, 'bytes': 0}, [])), mock.patch.object(p, 'command') as commands:
                self.assertEqual(p.main(), 0)
                commands.assert_not_called()
            evidence = json.loads(record.read_bytes())
            self.assertEqual(evidence['outcome'], 'preflight_only')
            self.assertFalse(evidence['accounts_changed'])
            self.assertFalse(evidence['apply'])

    def test_apply_transition_refusal_is_recorded_without_account_commands(self):
        with tempfile.TemporaryDirectory() as private:
            admission, record = Path(private, 'admission.json'), Path(private, 'record.json')
            admission.write_bytes(d.encoded(roster()))
            actual_open = os.open
            def redirect_record(path, *args, **kwargs):
                if path == '/var/lib/swarma-demo-provision.json':
                    path = record
                return actual_open(path, *args, **kwargs)
            with mock.patch.object(p.sys, 'argv', ['provision.py', '--admission', str(admission), '--source', '/source', '--record', '/var/lib/swarma-demo-provision.json', '--apply']), mock.patch.object(p.os, 'open', side_effect=redirect_record), mock.patch.object(p.demo, 'protected', side_effect=lambda *args, **kwargs: actual_open(admission, os.O_RDONLY | os.O_CLOEXEC)), mock.patch.object(p.demo, 'verified_invocation', side_effect=p.demo.Refusal('not_root')), mock.patch.object(p, 'command') as commands:
                self.assertEqual(p.main(), 1)
                commands.assert_not_called()
            evidence = json.loads(record.read_bytes())
            self.assertEqual(evidence['outcome'], 'refused')
            self.assertEqual(evidence['failure'], 'not_root')
            self.assertFalse(evidence['accounts_changed'])


class CopyTests(unittest.TestCase):
    def test_copy_positive_independent_content_and_administration_exclusion(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as destination:
            Path(source, 'dir').mkdir()
            Path(source, 'dir/code').write_bytes(b'public source\x00')
            Path(source, '.git').mkdir()
            Path(source, '.git/config').write_text('must not copy')
            first = p.manifest(source, time.monotonic() + 5)
            second = p.manifest(source, time.monotonic() + 5, destination)
            self.assertEqual(first, second)
            self.assertEqual(Path(destination, 'dir/code').read_bytes(), b'public source\x00')
            self.assertFalse(Path(destination, '.git').exists())
            self.assertNotEqual(Path(source, 'dir/code').stat().st_ino, Path(destination, 'dir/code').stat().st_ino)

    def test_links_hardlinks_special_files_and_expired_copy_refuse(self):
        for kind, code in (('symlink', 'path_is_link'), ('hardlink', 'copy_hardlink'), ('fifo', 'copy_special_file')):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as source:
                target = Path(source, 'content')
                target.write_bytes(b'public')
                if kind == 'symlink':
                    Path(source, 'bad').symlink_to('content')
                elif kind == 'hardlink':
                    os.link(target, Path(source, 'bad'))
                else:
                    os.mkfifo(Path(source, 'bad'))
                with self.assertRaises(p.demo.Refusal) as exc:
                    p.manifest(source, time.monotonic() + 5)
                self.assertEqual(exc.exception.code, code)
        with tempfile.TemporaryDirectory() as source:
            with self.assertRaises(p.demo.Refusal) as exc:
                p.manifest(source, time.monotonic() - 1)
            self.assertEqual(exc.exception.code, 'copy_bound_exceeded')

    def test_copy_exact_byte_and_entry_caps_positive_and_one_over_refusal(self):
        # Sparse file tests the real 256 MiB declared-size bound without retaining
        # a large artifact. Small patched caps exercise the complete read path.
        with tempfile.TemporaryDirectory() as source:
            with open(Path(source, 'large'), 'wb') as stream:
                stream.truncate(d.COPY_MAX)
            exact = p.manifest(source, time.monotonic() + 10)
            self.assertEqual(exact['bytes'], 256 * 1024 * 1024)
            with open(Path(source, 'large'), 'r+b') as stream:
                stream.truncate(d.COPY_MAX + 1)
            with self.assertRaises(p.demo.Refusal) as exc:
                p.manifest(source, time.monotonic() + 5)
            self.assertEqual(exc.exception.code, 'copy_bound_exceeded')
        with tempfile.TemporaryDirectory() as source:
            Path(source, 'a').write_bytes(b'1234')
            Path(source, 'b').write_bytes(b'5678')
            with mock.patch.object(p.demo, 'COPY_MAX', 8), mock.patch.object(p.demo, 'ENTRY_MAX', 2):
                self.assertEqual(p.manifest(source, time.monotonic() + 5)['bytes'], 8)
                Path(source, 'b').write_bytes(b'56789')
                with self.assertRaises(p.demo.Refusal):
                    p.manifest(source, time.monotonic() + 5)
                Path(source, 'b').write_bytes(b'5678')
                Path(source, 'c').write_bytes(b'')
                with self.assertRaises(p.demo.Refusal):
                    p.manifest(source, time.monotonic() + 5)

    def test_actual_twenty_thousand_entry_cap_and_one_over(self):
        with tempfile.TemporaryDirectory() as source:
            for i in range(20000):
                Path(source, str(i)).touch()
            self.assertEqual(p.manifest(source, time.monotonic() + 15)['entries'], 20000)
            Path(source, 'one-over').touch()
            with self.assertRaises(p.demo.Refusal) as exc:
                p.manifest(source, time.monotonic() + 15)
            self.assertEqual(exc.exception.code, 'copy_bound_exceeded')

    def test_actual_frozen_skill_link_is_refused_not_flattened(self):
        with self.assertRaises(p.demo.Refusal) as exc:
            p.manifest(str(DEMO_DIR.parent), time.monotonic() + 5)
        self.assertEqual(exc.exception.code, 'path_is_link')

    def test_operator_tool_capture_drains_beyond_both_caps_and_preserves_timeout(self):
        with tempfile.TemporaryDirectory() as home:
            script = "import os; os.write(1,b'O'*(2*1024*1024)); os.write(2,b'E'*(2*1024*1024))"
            result = p.command(['/usr/bin/python3', '-I', '-S', '-c', script], home)
            self.assertEqual(result['exit'], 0)
            self.assertEqual(len(result['stdout']), d.OUTPUT_MAX)
            self.assertEqual(len(result['stderr']), d.OUTPUT_MAX)
            self.assertEqual(result['stdout_bytes_drained'], 2 * d.OUTPUT_MAX)
            self.assertEqual(result['stderr_bytes_drained'], 2 * d.OUTPUT_MAX)
            self.assertTrue(result['output_over_cap'])
            self.assertFalse(result['drain_incomplete'])
            timeout = p.command(['/usr/bin/python3', '-I', '-S', '-c', 'import time; time.sleep(10)'], home, timeout=0.1)
            self.assertTrue(timeout['timeout'])
            self.assertEqual(timeout['exit'], -9)
            self.assertLess(timeout['elapsed_seconds'], 1.5)

    def test_fresh_git_has_no_hooks_remotes_helpers_or_global_config(self):
        with tempfile.TemporaryDirectory() as path, tempfile.TemporaryDirectory() as home:
            Path(home, '.gitconfig').write_text('[credential]\n\thelper = must-not-inherit\n')
            result = p.fresh_git(path, home)
            self.assertEqual(result['exit'], 0)
            self.assertEqual(list(Path(path, '.git/hooks').glob('*')), [])
            config = Path(path, '.git/config').read_text()
            self.assertNotIn('must-not-inherit', config)
            self.assertNotIn('[remote ', config)
            self.assertNotIn('include', config.lower())
            self.assertIn('hooksPath = /dev/null', config)
            self.assertIn('helper = ', config)
            self.assertFalse(Path(path, '.git/objects/info/alternates').exists())


if __name__ == '__main__':
    unittest.main()
