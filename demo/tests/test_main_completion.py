"""Actual main and private Store; time, identity and process effects are fake."""
import copy
import errno
import json
import os
import sys
import unittest
from contextlib import ExitStack, contextmanager
from unittest import mock
import test_demo as f

d = f.d


class MainCompletionTests(unittest.TestCase):
    def run_case(self, kind='launch', close_cost=0., serialize_cost=0., setup_cost=0.,
                 fault=None, replay=False):
        with f.StateTests().fixture() as (disk, root):
            r = f.roster()
            store_type = type(disk)
            gen = r['accounts'][0]['generation']
            receipts = root / 'receipts'
            receipts.mkdir(mode=0o700)
            events, wires, completed, closes = [], [], [], []

            class MainStore(f.MemoryStore):
                hook = None
                @contextmanager
                def locked(self, name='transition.lock'):
                    with super().locked(name), disk.locked(name):
                        yield
                def read(self, generation):
                    return disk.read(generation)
                def write(self, generation, value):
                    super().write(generation, value)
                    if self.hook:
                        self.hook(value, lambda: disk.write(generation, value))
                    else:
                        disk.write(generation, value)
                def receipt(self, generation, execution, value):
                    super().receipt(generation, execution, value)
                    disk.receipt(generation, execution, value)

            s = MainStore(r)
            b = f.FakeRunner(r, s)
            disk.write(gen, s.data[gen])
            first_kill = 100. if kind == 'kill' else None
            bound = {'launch': 110., 'whole': 145., 'kill': 105.}[kind]
            request = f.launch_request() if kind == 'launch' else f.stop_request(0)

            def protected(path, **kwargs):
                self.assertEqual(path, d.STATE + '/receipts/' + gen)
                return os.open(receipts, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

            with mock.patch.object(d, 'protected', protected):
                if kind != 'launch':
                    d.launch(r, 1101, f.launch_request(), b'opaque', s, b, 100.)
                    b.members.clear()
                    rec = s.read(gen)
                    rec['stop'] = dict(request=request, started_at=d.utc(), started_mono=100.,
                                       grace_seconds=0, kill_mono=first_kill, outcome='pending',
                                       events=[], signalled=0, killed=0, last_scan_complete=False,
                                       remaining=None, finished_at=None, elapsed_seconds=None)
                    with s.locked():
                        s.write(gen, rec)
                    b.now = bound - 2.5

                published = []
                def publication(value, write):
                    self.assertFalse(published, 'no corrective publication')
                    write()
                    candidate = (value.get('launch_publication') if kind == 'launch'
                                 else value.get('stop', {}).get('completion_publication'))
                    if candidate:
                        published.append(copy.deepcopy(value))
                        b.now = bound - .25
                        events.append('publication')
                        if fault == 'publication':
                            raise OSError(errno.EIO, 'synthetic publication uncertainty')
                s.hook = publication
                real_close, real_encoded, real_write = store_type.close, d.encoded, os.write
                real_complete = getattr(d, 'complete', None)
                real_response = d.response
                response_records = []
                encoded_answers = []

                def response(request_id, record, launching):
                    response_records.append(copy.deepcopy(record))
                    return real_response(request_id, record, launching)

                def close():
                    self.assertFalse(s.leases)
                    real_close(disk)
                    b.now += close_cost
                    closes.append(b.now)
                    events.append('store-closed')
                    if fault in ('close', 'operation-and-close'):
                        raise OSError(errno.EIO, 'synthetic close uncertainty')
                s.close = close

                def encode(value):
                    if isinstance(value, dict) and 'ok' in value:
                        events.append('serialize')
                        encoded_answers.append(copy.deepcopy(value))
                        if len(encoded_answers) == 1:
                            b.now += serialize_cost
                        if fault == 'serialize' and len(encoded_answers) == 1:
                            raise ValueError('synthetic serialization failure')
                        if fault == 'serialize-pending' and len(encoded_answers) == 2:
                            raise ValueError('synthetic pending serialization failure')
                        if fault == 'serialize-all':
                            raise ValueError('synthetic serializer unavailable')
                    return real_encoded(value)

                def complete(record, launching, finished):
                    result = real_complete(record, launching, finished)
                    if closes:
                        events.append('complete')
                        completed.append(copy.deepcopy(result))
                    return result

                def blocking(fd, value):
                    self.assertEqual((fd, value), (1, False))
                    events.append('stdout-setup')
                    b.now += setup_cost
                    if fault == 'stdout-setup':
                        raise OSError(errno.EBADF, 'synthetic output unavailable')

                def output(fd, data):
                    if fd != 1:
                        return real_write(fd, data)
                    events.append('write')
                    self.assertEqual(len(closes), 1)
                    if fault == 'write':
                        raise BrokenPipeError(errno.EPIPE, 'synthetic lost response')
                    if fault == 'short-write':
                        return len(data) - 1
                    wires.append(json.loads(data))
                    return len(data)

                def operation(*args, **kwargs):
                    if fault == 'operation-refusal':
                        d.refuse('state_conflict')
                    raise OSError(errno.EIO, 'synthetic operation failure')

                with ExitStack() as stack:
                    for obj, name, value in (
                        (d, 'close_except', lambda *_: None),
                        (d, 'verified_invocation', lambda *_: 1101),
                        (d, 'load_roster', lambda: r), (d, 'Store', lambda: s),
                        (d, 'Native', lambda _: b),
                        (d, 'intake', lambda *_: real_encoded(request)),
                        (d, 'encoded', encode), (d, 'response', response),
                        (d.time, 'monotonic', b.clock),
                        (d.os, 'chdir', lambda *_: None), (d.os, 'umask', lambda *_: None),
                        (d.os, 'set_blocking', blocking), (d.os, 'write', output)):
                        stack.enter_context(mock.patch.object(obj, name, value))
                    if real_complete:
                        stack.enter_context(mock.patch.object(d, 'complete', complete))
                    if fault in ('operation', 'operation-refusal', 'operation-and-close'):
                        stack.enter_context(mock.patch.object(d, 'launch' if kind == 'launch' else 'stop', operation))
                    stack.enter_context(mock.patch.dict(os.environ, dict(os.environ), clear=True))
                    stack.enter_context(mock.patch.object(sys, 'argv', [d.LAUNCHER if kind == 'launch' else d.HELPER]))
                    try:
                        try:
                            code = d.main([])
                        except (d.Refusal, OSError, ValueError, TypeError) as exc:
                            self.fail('main leaked a defined failure: ' + type(exc).__name__)
                    finally:
                        disk.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

            print(json.dumps(dict(kind=kind, close_cost=close_cost, serialize_cost=serialize_cost,
                                  setup_cost=setup_cost, fault=fault, original_origin=100., cutoff=bound,
                                  close_finished=closes, at_output=b.now, events=events, wire=wires, exit=code)))
            self.assertEqual(len(closes), 1)
            self.assertFalse(s.leases)
            self.assertFalse(s.transition)
            if fault:
                self.assertEqual(code, 1)
                if fault in ('serialize-all', 'write', 'short-write'):
                    self.assertEqual(wires, [])
                else:
                    self.assertEqual(len(wires), 1)
                    self.assertFalse(wires[0]['ok'])
                    expected = 'state_conflict' if fault == 'operation-refusal' else 'state_unavailable'
                    self.assertEqual(wires[0]['error']['code'], expected)
            else:
                self.assertEqual(len(published), 1)
                self.assertEqual(len(wires), 1)
                self.assertEqual(wires[0]['ok'], b.now < bound,
                                 'main succeeded at/after its original cutoff')
                self.assertEqual(code, 0 if b.now < bound else 1)
                final = completed[0] if completed else response_records[0]
                elapsed = final['launch_elapsed_seconds'] if kind == 'launch' else final['stop']['elapsed_seconds']
                self.assertEqual(elapsed, b.now - 100.)
                if completed:
                    self.assertEqual(len(completed), 1)
                    self.assertGreater(events.index('complete'), events.index('store-closed'))
                    self.assertGreater(events.index('complete'), max(i for i, e in enumerate(events) if e == 'serialize'))
                durable = disk.read(gen)
                if kind == 'launch':
                    self.assertEqual(durable['launch_outcome'], 'unknown')
                    self.assertIsNone(durable['launch_elapsed_seconds'])
                    self.assertEqual(final['launch_started_mono'], 100.)
                else:
                    self.assertEqual(durable['stop']['outcome'], 'pending')
                    self.assertIsNone(durable['stop']['elapsed_seconds'])
                    self.assertIsNone(durable['stop']['finished_at'])
                    self.assertEqual(final['stop']['started_mono'], 100.)
                    self.assertEqual(final['stop']['kill_mono'], first_kill)
                    self.assertEqual(final['stop']['deadline_missed'], b.now >= 145.)
                    self.assertEqual(final['stop']['final_scan_deadline_missed'], kind == 'kill' and b.now >= 105.)
                self.assertEqual(b.spawn_count, 1)
                self.assertEqual(json.loads((receipts / 'EX-fixture.json').read_bytes()), durable['receipt'])
                if replay:
                    before = (root / (gen + '.json')).read_bytes()
                    calls = len(b.calls)
                    s.hook = lambda *_: self.fail('replay wrote state')
                    b.scan = b.signal = b.spawn = lambda *_: self.fail('replay initiated a process effect')
                    b.now = bound + .5
                    result = (d.launch(r, 1101, request, b'opaque', s, b, b.now) if kind == 'launch'
                              else d.stop(r, 1101, request, s, b, started=b.now))
                    self.assertFalse(d.response(request['request_id'], result, kind == 'launch')['ok'])
                    self.assertEqual((root / (gen + '.json')).read_bytes(), before)
                    self.assertEqual(len(b.calls), calls)
                    self.assertEqual(b.spawn_count, 1)
            print(json.dumps(dict(kind=kind, close_cost=close_cost, serialize_cost=serialize_cost,
                                  setup_cost=setup_cost, fault=fault, original_origin=100., cutoff=bound,
                                  close_finished=closes, events=events, wire=wires, exit=code,
                                  replay_no_effects=replay)))

    def test_main_store_close_all_three_cutoff_neighbours(self):
        for kind in ('launch', 'whole', 'kill'):
            for cost in (0., .125, .25, .5):
                with self.subTest(kind=kind, cost=cost):
                    self.run_case(kind, close_cost=cost, replay=True)

    def test_main_serialization_all_three_cutoff_neighbours(self):
        for kind in ('launch', 'whole', 'kill'):
            for cost in (0., .125, .25, .5):
                with self.subTest(kind=kind, cost=cost):
                    self.run_case(kind, serialize_cost=cost)

    def test_main_output_setup_and_combined_costs(self):
        for kind in ('launch', 'whole', 'kill'):
            for costs in ((0., 0., .125), (0., 0., .25), (0., 0., .5),
                          (.125, .0625, .0625), (.125, .125, .125)):
                with self.subTest(kind=kind, costs=costs):
                    self.run_case(kind, close_cost=costs[0], serialize_cost=costs[1], setup_cost=costs[2])

    def test_main_failures_cleanup_and_no_success_output(self):
        for kind in ('launch', 'whole', 'kill'):
            for fault in ('operation', 'operation-refusal', 'operation-and-close', 'publication',
                          'close', 'serialize', 'serialize-pending', 'serialize-all',
                          'stdout-setup', 'write', 'short-write'):
                with self.subTest(kind=kind, fault=fault):
                    self.run_case(kind, close_cost=.5, fault=fault)
