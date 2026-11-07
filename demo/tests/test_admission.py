"""Real roster admission through both entries; synthetic ownership, no root effects."""
import copy
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from test_demo import d, roster


class NextStage(BaseException):
    """The admitted invocation reached request intake; never execute a request."""


class AdmissionTests(unittest.TestCase):
    @contextmanager
    def fixture(self, entry):
        with tempfile.TemporaryDirectory() as private, ExitStack() as stack:
            path = Path(private) / 'roster.json'
            trusted = roster()
            real_fstat = os.fstat
            wires = []

            def ownership(fd):
                # Keep real type, mode, and link count. Only root ownership is
                # synthetic; protected's descriptor walk and reads remain real.
                info = real_fstat(fd)
                return types.SimpleNamespace(st_uid=0, st_gid=0,
                                             st_mode=info.st_mode,
                                             st_nlink=info.st_nlink)

            def output(fd, data):
                self.assertEqual(fd, 1)
                wires.append(json.loads(data))
                return len(data)

            guards = {}
            for obj, name in ((d, 'Store'), (d, 'Native'), (d, 'launch'),
                              (d, 'stop'), (d, 'spawn'), (d, 'write_launch_record'),
                              (d.os, 'fork'), (d.os, 'execve'), (d.os, 'kill')):
                guard = stack.enter_context(mock.patch.object(
                    obj, name, side_effect=AssertionError('unexpected effect: ' + name)))
                guards[name] = guard
            stack.enter_context(mock.patch.object(d, 'ROSTER', str(path)))
            stack.enter_context(mock.patch.object(d.os, 'fstat', side_effect=ownership))
            stack.enter_context(mock.patch.object(d, 'close_except'))
            invocation = stack.enter_context(mock.patch.object(
                d, 'verified_invocation', return_value=trusted['dispatcher']['uid']))
            boot = stack.enter_context(mock.patch.object(
                d, 'current_boot', return_value=trusted['boot_id']))
            intake = stack.enter_context(mock.patch.object(d, 'intake', side_effect=NextStage))
            stack.enter_context(mock.patch.object(d.os, 'chdir'))
            stack.enter_context(mock.patch.object(d.os, 'umask'))
            stack.enter_context(mock.patch.object(d.os, 'set_blocking'))
            stack.enter_context(mock.patch.object(d.os, 'write', side_effect=output))
            stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
            stack.enter_context(mock.patch.object(sys, 'argv', [entry]))

            def run(candidate, current_boot, admitted):
                # The same private file is reopened by the real loader each time.
                path.write_text(json.dumps(candidate), encoding='ascii')
                path.chmod(0o644)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
                before = path.read_bytes()
                wires.clear()
                boot.reset_mock()
                intake.reset_mock()
                invocation.reset_mock()
                boot.return_value = current_boot
                if admitted:
                    with self.assertRaises(NextStage):
                        d.main([])
                    self.assertEqual(wires, [])
                    intake.assert_called_once()
                    self.assertEqual(intake.call_args.args[:2],
                                     (0, d.LAUNCH_MAX if entry == d.LAUNCHER else d.STOP_MAX))
                else:
                    self.assertEqual(d.main([]), 1)
                    self.assertEqual(len(wires), 1)
                    self.assertEqual(wires[0]['request_id'], None)
                    self.assertIs(wires[0]['ok'], False)
                    self.assertEqual(wires[0]['error']['code'], 'qualification_required')
                    intake.assert_not_called()
                invocation.assert_called_once()
                boot.assert_called_once_with()
                for guard in guards.values():
                    guard.assert_not_called()
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(list(Path(private).iterdir()), [path])

            yield trusted, run

    def test_each_withdrawn_runtime_flag_before_effects_both_entries(self):
        for entry in (d.LAUNCHER, d.HELPER):
            with self.subTest(entry=entry), self.fixture(entry) as (trusted, run):
                for flag in ('admitted', 'inventory_qualified',
                             'creation_exclusion_qualified', 'interpreter_qualified'):
                    with self.subTest(flag=flag):
                        withdrawn = copy.deepcopy(trusted)
                        withdrawn['runtime'][flag] = False
                        run(withdrawn, trusted['boot_id'], admitted=False)
                        run(trusted, trusted['boot_id'], admitted=True)

    def test_prior_boot_before_effects_and_matching_neighbor_both_entries(self):
        for entry in (d.LAUNCHER, d.HELPER):
            with self.subTest(entry=entry), self.fixture(entry) as (trusted, run):
                # Only current boot changes: the exact same valid roster bytes
                # and all four true runtime flags are used on both invocations.
                run(trusted, '22222222-2222-2222-2222-222222222222', admitted=False)
                run(trusted, trusted['boot_id'], admitted=True)


if __name__ == '__main__':
    unittest.main()
