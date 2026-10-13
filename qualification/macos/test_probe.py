"""Run these tests on the hosted runners. Importing probe never runs a workload."""
import unittest
from unittest.mock import patch
import probe


class RefusalTests(unittest.TestCase):
    def setUp(self):
        self.env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                    'RUNNER_OS': 'macOS', 'PROBE_RUNNER_LABEL': 'macos-14'}

    def test_hosted_control_reachable(self):
        probe.guard(self.env, major='14', euid=0)
        self.env['PROBE_RUNNER_LABEL'] = 'macos-15'
        probe.guard(self.env, major='15', euid=0)

    def test_local_and_self_hosted_refuse_before_any_os_call(self):
        for field in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'PROBE_RUNNER_LABEL'):
            env = self.env.copy()
            env.pop(field)
            with self.subTest(field=field), patch('probe.subprocess.check_output') as os_call:
                with self.assertRaises(RuntimeError):
                    probe.guard(env)
                os_call.assert_not_called()
        for runner in ('self-hosted', ''):
            env = dict(self.env, RUNNER_ENVIRONMENT=runner)
            with self.assertRaises(RuntimeError):
                probe.guard(env, major='14', euid=0)

    def test_narrow_os_scope_and_root_requirement(self):
        for label, major, euid in (('macos-13', '13', 0), ('macos-14', '15', 0), ('macos-14', '14', 501)):
            with self.assertRaises(RuntimeError):
                probe.guard(dict(self.env, PROBE_RUNNER_LABEL=label), major=major, euid=euid)

    def test_valid_control_and_permission_denial(self):
        self.assertEqual('hard', probe.deny_verdict([{'rc': 0}], [{'rc': 1, 'stderr': 'Operation not permitted'}]))

    def test_absent_or_failing_control_is_unknown(self):
        refused = [{'rc': 1, 'stderr': 'Permission denied'}]
        for control in ([], [{'rc': 1}], [{'rc': 124}], [{'rc': 127}], [{}]):
            self.assertEqual('unknown', probe.deny_verdict(control, refused))

    def test_timeout_crash_missing_binary_or_syntax_error_is_not_denial(self):
        for result in ({'rc': 124}, {'rc': -9}, {'rc': 127, 'stderr': 'Permission denied'},
                       {'rc': 1, 'stderr': 'syntax error'}, {}):
            self.assertEqual('unknown', probe.deny_verdict([{'rc': 0}], [result]))

    def test_narrowing_coverage_requires_every_attempt_to_refuse(self):
        refused = {'rc': 1, 'stderr': 'Permission denied'}
        self.assertEqual('unknown', probe.deny_verdict([{'rc': 0}], []))
        self.assertEqual('unknown', probe.deny_verdict([{'rc': 0}], [refused, {'rc': 1}]))
        self.assertEqual('absent', probe.deny_verdict([{'rc': 0}], [refused, {'rc': 0}]))

    def test_row_inventory_has_exact_brief_coverage(self):
        expected = ('ACCT', 'EXEC', 'NET', 'DNS', 'PF', 'NPROC', 'MEM-RLIMIT', 'MEM-WATCH',
                    'CPU-QOS', 'DISK', 'VIS', 'CRON', 'LAUNCHD', 'KILL', 'SOCK')
        self.assertEqual(expected, probe.ROWS)
        self.assertEqual(set(expected), set(probe.FUNCTIONS))
        self.assertEqual(set(expected), set(probe.BOUNDS))
        self.assertTrue(all(0 < x <= 180 for x in probe.BOUNDS.values()))

    def test_failed_and_malformed_process_reads_are_not_absence(self):
        for result in ({'rc': 1, 'stdout': ''}, {'rc': 0, 'stdout': 'malformed'}, {'rc': 124}):
            with patch('probe.run', return_value=result), self.assertRaises(RuntimeError):
                probe.pid_inventory(39001)
        with patch('probe.run', return_value={'rc': 0, 'stdout': '501 10\n39001 20\n'}):
            self.assertEqual([20], probe.pid_inventory(39001))

    def test_redact_personal_paths(self):
        self.assertNotIn('/Users/example', probe.redact('/Users/example/work/file'))


if __name__ == '__main__':
    unittest.main()
