"""Exact terminal replay: real private files/flocks, synthetic root/processes."""
import copy
import errno
import json
import os
import sys
import unittest
from contextlib import ExitStack, contextmanager
from unittest import mock
import test_demo as f
import test_publication as publication

d = f.d


class TerminalReplayTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with publication.PublicationTests().setup_disk() as (r, s, b, root):
            disk = d.Store.__new__(d.Store)
            disk.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            original = s.locked
            @contextmanager
            def locked(name='transition.lock'):
                with disk.locked(name), original(name):
                    yield
            s.locked = locked
            try:
                d.launch(r, 1101, f.launch_request(), b'opaque', s, b, b.now)
                yield r, s, b, root
            finally:
                disk.close()

    def snapshot(self, root):
        return {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns,
                         p.stat().st_ctime_ns) for p in root.iterdir()}

    def forbid_effects(self, s, b):
        s.hook = lambda *_: self.fail('replay wrote state')
        b.scan = b.signal = b.spawn = b.check = b.receipt_matches = lambda *_: self.fail('replay touched processes')

    def test_completed_exact_replay_returns_same_wire_without_writes_or_signals(self):
        with self.fixture() as (r, s, b, root):
            request = f.stop_request(0)
            first = d.stop(r, 1101, request, s, b)
            expected = d.response(request['request_id'], first, False)
            self.assertTrue(expected['ok'])
            calls = list(b.calls)
            before = self.snapshot(root)
            self.forbid_effects(s, b)
            b.now += 1000  # the historical result does not get re-budgeted
            with mock.patch.object(d.os, 'write', side_effect=AssertionError('replay write syscall')):
                for _ in range(2):
                    replay = d.stop(r, 1101, request, s, b)
                    self.assertEqual(d.encoded(d.response(request['request_id'], replay, False)), d.encoded(expected))
                    self.assertEqual(replay['stop']['started_mono'], first['stop']['started_mono'])
                    self.assertEqual(replay['stop']['kill_mono'], first['stop']['kill_mono'])
                    self.assertEqual(replay['stop']['elapsed_seconds'], first['stop']['elapsed_seconds'])
            self.assertEqual(b.calls, calls)
            self.assertEqual(self.snapshot(root), before)
            print(json.dumps(dict(case='terminal_exact', ok=True, replay_count=2,
                                  new_signals=0, new_writes=0, original_origin=first['stop']['started_mono'],
                                  replay_at=b.now, response=expected)))

    def test_wrong_bytes_or_identity_refused_even_if_json_equivalent(self):
        with self.fixture() as (r, s, b, root):
            request = f.stop_request()
            wire = d.encoded(request) + b'\n'
            first = d.stop(r, 1101, request, s, b, request_bytes=wire)
            expected = d.response(request['request_id'], first, False)
            before = self.snapshot(root)
            self.forbid_effects(s, b)
            variants = [(request, d.encoded(request)),
                        (request, json.dumps(request, indent=2).encode()),
                        (request, wire + b' ')]
            changed_id = copy.deepcopy(request); changed_id['request_id'] = 'different-stop'
            variants.append((changed_id, d.encoded(changed_id)))
            changed_args = f.stop_request(9)
            variants.append((changed_args, d.encoded(changed_args)))
            for obj, raw in variants:
                with self.subTest(raw=raw), self.assertRaises(d.Refusal) as raised:
                    d.stop(r, 1101, obj, s, b, request_bytes=raw)
                self.assertEqual(raised.exception.code, 'request_id_conflict')
                self.assertEqual(self.snapshot(root), before)
            replay = d.stop(r, 1101, request, s, b, request_bytes=wire)
            self.assertEqual(d.response(request['request_id'], replay, False), expected)
            self.assertEqual(self.snapshot(root), before)
            print(json.dumps(dict(case='wrong_bytes_identity', refused=len(variants), new_writes=0)))

    def test_interrupted_unknown_publication_stays_held_without_effects(self):
        for phase in ('pending-publication', 'before-terminal-record'):
            with self.subTest(phase=phase), self.fixture() as (r, s, b, root):
                request = f.stop_request(0)
                def interrupt(value, write):
                    ev = value.get('stop') or {}
                    if phase == 'pending-publication' and ev.get('completion_publication'):
                        write()
                        raise publication.Interrupted()
                    if phase == 'before-terminal-record' and ev.get('terminal_outcome'):
                        raise publication.Interrupted()
                    write()
                s.hook = interrupt
                with self.assertRaises(publication.Interrupted):
                    d.stop(r, 1101, request, s, b)
                durable = s.read('1' * 32)
                self.assertNotIn('terminal_outcome', durable['stop'])
                before = self.snapshot(root)
                self.forbid_effects(s, b)
                b.now += 100
                replay = d.stop(r, 1101, request, s, b)
                self.assertFalse(d.response(request['request_id'], replay, False)['ok'])
                self.assertEqual(self.snapshot(root), before)
                self.assertEqual(replay['stop']['started_mono'], durable['stop']['started_mono'])
                print(json.dumps(dict(case='unknown_interruption', phase=phase, held=True,
                                      new_signals=0, new_writes=0)))

    def test_recorded_completion_survives_lost_confirmation_reply(self):
        for fault in ('crash-after-install', 'eio-after-install', 'late-confirmation'):
            with self.subTest(fault=fault), self.fixture() as (r, s, b, root):
                request = f.stop_request(0)
                def confirmation(value, write):
                    write()
                    if (value.get('stop') or {}).get('terminal_outcome'):
                        if fault == 'crash-after-install':
                            raise publication.Interrupted()
                        if fault == 'eio-after-install':
                            raise OSError(errno.EIO, 'synthetic confirmation uncertainty')
                        b.now = 145.
                s.hook = confirmation
                if fault == 'late-confirmation':
                    result = d.stop(r, 1101, request, s, b)
                    self.assertFalse(d.response(request['request_id'], result, False)['ok'])
                else:
                    with self.assertRaises(publication.Interrupted if fault == 'crash-after-install' else OSError):
                        d.stop(r, 1101, request, s, b)
                terminal = s.read('1' * 32)['stop']['terminal_outcome']
                self.assertLess(terminal['elapsed_seconds'], d.STOP_WHOLE)
                before = self.snapshot(root)
                self.forbid_effects(s, b)
                b.now += 100
                replay = d.stop(r, 1101, request, s, b)
                self.assertTrue(d.response(request['request_id'], replay, False)['ok'])
                self.assertEqual(self.snapshot(root), before)
                print(json.dumps(dict(case='recorded_before_lost_reply', fault=fault,
                                      recorded_elapsed=terminal['elapsed_seconds'], new_signals=0, new_writes=0)))

    def test_original_custody_and_zero_generation_still_refused(self):
        with self.fixture() as (r, s, b, root):
            request = f.stop_request()
            d.stop(r, 1101, request, s, b)
            self.forbid_effects(s, b)
            before = self.snapshot(root)
            for change in ('caller', 'boot', 'dispatcher', 'account', 'execution', 'zero'):
                other = copy.deepcopy(r); obj = copy.deepcopy(request); caller = 1101
                if change == 'caller': caller = 1001
                if change == 'boot': other['boot_id'] = '22222222-2222-2222-2222-222222222222'
                if change == 'dispatcher': other['dispatcher']['generation'] = 'e' * 32
                if change == 'account': other['accounts'][0]['copy_digest'] = 'c' * 64
                if change == 'execution': obj['args']['execution_id'] = 'other-execution'
                if change == 'zero': obj['args']['generation'] = '0' * 32
                with self.subTest(change=change), self.assertRaises(d.Refusal):
                    d.stop(other, caller, obj, s, b)
                self.assertEqual(self.snapshot(root), before)

    def test_legacy_unconfirmed_record_is_never_promoted(self):
        with self.fixture() as (r, s, b, root):
            request = f.stop_request()
            d.stop(r, 1101, request, s, b)
            gen = r['accounts'][0]['generation']
            saved = s.read(gen)
            del saved['stop']['terminal_outcome']
            del saved['stop']['request_digest']
            saved['stop']['outcome'] = 'absent'  # historical optimistic format
            with s.locked(): s.write(gen, saved)
            before = self.snapshot(root)
            self.forbid_effects(s, b)
            replay = d.stop(r, 1101, request, s, b)
            self.assertFalse(d.response(request['request_id'], replay, False)['ok'])
            self.assertEqual(self.snapshot(root), before)

    def test_confirmation_admission_cannot_cross_original_bounds(self):
        for first_kill in (False, True):
            with self.subTest(first_kill=first_kill), self.fixture() as (r, s, b, root):
                request = f.stop_request(0 if first_kill else 10)
                lock = s.locked
                leases = 0
                @contextmanager
                def delayed(name='transition.lock'):
                    nonlocal leases
                    with lock(name):
                        if name.endswith('.stop.lock'):
                            leases += 1
                            if leases == 2:
                                b.now = 105. if first_kill else 145.
                        yield
                s.locked = delayed
                stopped = d.stop(r, 1101, request, s, b)
                self.assertFalse(d.response(request['request_id'], stopped, False)['ok'])
                self.assertNotIn('terminal_outcome', s.read('1' * 32)['stop'])
                before = self.snapshot(root)
                self.forbid_effects(s, b)
                replay = d.stop(r, 1101, request, s, b)
                self.assertFalse(d.response(request['request_id'], replay, False)['ok'])
                self.assertEqual(self.snapshot(root), before)
                print(json.dumps(dict(case='confirmation_original_bound', first_kill=first_kill,
                                      original_origin=100., cutoff=b.now, held=True)))

    def test_entrypoint_passes_original_bytes_and_replays_frozen_wire(self):
        with self.fixture() as (r, s, b, root):
            request = f.stop_request()
            wire = json.dumps(request, indent=2).encode() + b'\n'
            stopped = d.stop(r, 1101, request, s, b, request_bytes=wire)
            expected = d.response(request['request_id'], stopped, False)
            self.forbid_effects(s, b)
            b.now += 100
            # Privileged invocation/NSS and stdout are synthetic. Store reads and
            # flock descriptors still use the actual private filesystem.
            s.close = lambda: None
            for raw, ok in ((wire, True), (d.encoded(request), False)):
                outputs = []
                before = self.snapshot(root)
                def output(fd, data):
                    self.assertEqual(fd, 1)
                    outputs.append(json.loads(data))
                    return len(data)
                with ExitStack() as stack:
                    for obj, name, value in (
                        (d, 'close_except', lambda *_: None),
                        (d, 'verified_invocation', lambda *_: 1101),
                        (d, 'load_roster', lambda: r), (d, 'Store', lambda: s),
                        (d, 'Native', lambda _: b), (d, 'intake', lambda *_: raw),
                        (d.time, 'monotonic', b.clock),
                        (d.os, 'chdir', lambda *_: None), (d.os, 'umask', lambda *_: None),
                        (d.os, 'set_blocking', lambda *_: None), (d.os, 'write', output)):
                        stack.enter_context(mock.patch.object(obj, name, value))
                    stack.enter_context(mock.patch.dict(os.environ, dict(os.environ), clear=True))
                    stack.enter_context(mock.patch.object(sys, 'argv', [d.HELPER]))
                    code = d.main([])
                self.assertEqual(code, 0 if ok else 1)
                self.assertEqual(len(outputs), 1)
                if ok:
                    self.assertEqual(outputs[0], expected)
                else:
                    self.assertEqual(outputs[0]['error']['code'], 'request_id_conflict')
                self.assertEqual(self.snapshot(root), before)

    def test_legacy_unfinished_record_without_byte_binding_holds(self):
        with self.fixture() as (r, s, b, root):
            request = f.stop_request()
            d.stop(r, 1101, request, s, b)
            gen = r['accounts'][0]['generation']
            saved = s.read(gen)
            for key in ('terminal_outcome', 'request_digest', 'completion_publication'):
                del saved['stop'][key]
            saved['stop']['remaining'] = None
            saved['stop']['last_scan_complete'] = False
            with s.locked(): s.write(gen, saved)
            before = self.snapshot(root)
            self.forbid_effects(s, b)
            replay = d.stop(r, 1101, request, s, b)
            self.assertFalse(d.response(request['request_id'], replay, False)['ok'])
            self.assertEqual(self.snapshot(root), before)
