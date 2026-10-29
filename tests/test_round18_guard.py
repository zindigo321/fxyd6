"""Parent guard policy without installing persistent hooks into the test worker."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.round18 import guard
from src.round18.binding import ROOT
from src.round18.supervise import PROBE_CODE, PROBE_MODES


class CoordinatorGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND18_TEST_ROOT'))
        self.work = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def worker(self, job='science'):
        return [sys.executable, '-X', 'utf8', '-B', '-m', 'src.round18.worker',
            '--work', str(self.work), '--out', str(self.work/'attempts/one/output'), '--job', job]

    def test_only_exact_workers_for_this_work_and_cwd_are_allowed(self):
        for job in ['science', 'tests', 'legacy', 'guards']:
            self.assertTrue(guard.coordinator_command_allowed(self.worker(job), self.work, ROOT))
        wrong = [self.worker()+['--unexpected'], self.worker('recommend'), self.worker()]
        wrong[-1][9] = str(self.work.parent/'other/attempts/one/output')
        for argv in wrong:
            self.assertFalse(guard.coordinator_command_allowed(argv, self.work, ROOT))
        self.assertFalse(guard.coordinator_command_allowed(self.worker(), self.work, self.work))

    def test_only_two_exact_probe_commands_and_their_own_pid_files_are_allowed(self):
        for mode in PROBE_MODES:
            folder = self.work/'supervision'/mode
            argv = [sys.executable, '-X', 'utf8', '-B', '-c', PROBE_CODE, str(folder/'created_pid.json'), mode]
            self.assertTrue(guard.coordinator_command_allowed(argv, self.work, folder))
            argv[5] += ';print(1)'
            self.assertFalse(guard.coordinator_command_allowed(argv, self.work, folder))
            argv[5] = PROBE_CODE
            argv[6] = str(self.work.parent/'unrelated_pid.json')
            self.assertFalse(guard.coordinator_command_allowed(argv, self.work, folder))

    def capture(self):
        callbacks = []
        with patch.object(sys, 'addaudithook', side_effect=callbacks.append), \
             patch.object(sys, 'meta_path', list(sys.meta_path)):
            result = guard.install_coordinator_guard(self.work)
        self.assertTrue(result['installed'])
        self.assertEqual(len(callbacks), 1)
        return callbacks[0]

    def test_audit_allows_reads_and_work_writes_but_rejects_external_mutation(self):
        audit = self.capture()
        audit('open', (str(self.work.parent/'read_only_evidence'), 'r', 0))
        audit('open', (str(self.work/'result.json'), 'w', os.O_WRONLY | os.O_CREAT))
        with self.assertRaisesRegex(PermissionError, 'ROUND18_GUARD_WRITE_SCOPE'):
            audit('open', (str(self.work.parent/'outside.json'), 'w', os.O_WRONLY | os.O_CREAT))
        with self.assertRaisesRegex(PermissionError, 'ROUND18_GUARD_MUTATION_SCOPE'):
            audit('os.rename', (str(self.work/'source'), str(self.work.parent/'outside')))

    def test_native_network_and_archived_vendor_exec_are_rejected(self):
        audit = self.capture()
        events = [('import', ('comtypes.client', None, None, None, None), 'NATIVE_IMPORT'),
            ('socket.connect', (None, ('example.invalid', 443)), 'NETWORK'),
            ('exec', (compile('pass', str(ROOT/'work/round17/old/materialized/vendor_code.py'), 'exec'),), 'VENDOR_EXECUTION')]
        for event, args, reason in events:
            with self.assertRaisesRegex(PermissionError, 'ROUND18_GUARD_'+reason):
                audit(event, args)

    def test_actual_popen_audit_records_allowed_argv_and_rejects_a_generic_python_child(self):
        audit = self.capture()
        audit('subprocess.Popen', (sys.executable, self.worker('tests'), str(ROOT), {}))
        with self.assertRaisesRegex(PermissionError, 'ROUND18_GUARD_UNAPPROVED_SUBPROCESS'):
            audit('subprocess.Popen', (sys.executable, [sys.executable, '-c', 'pass'], str(ROOT), {}))
        rows = [json.loads(line) for line in (self.work/'coordinator_guard.jsonl').read_text(encoding='utf8').splitlines()]
        self.assertEqual([row['kind'] for row in rows], ['guard_installed', 'allowed_offline_subprocess', 'unexpected_denial'])
        self.assertEqual(rows[1]['detail']['argv'], self.worker('tests'))


if __name__ == '__main__':
    unittest.main()
