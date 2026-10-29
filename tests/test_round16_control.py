"""R16 durable 60004-space prefixes and truthful interrupted-file handling."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from src.round13.common import EvidenceError, write
from src.round16.control import Lifecycle, BudgetExceeded, Status, classify
from src.round16.seal import prefix_counts, durable_records


class DurablePrefixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND16_TEST_ROOT'))
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def emit(self, name, rows):
        (self.root/(name+'.jsonl')).write_text(''.join(json.dumps(row)+'\n' for row in rows), encoding='utf8')

    def test_cutoff_preserves_actual_single_swap_prefix_and_unknown(self):
        write(self.root/'progress.json', dict(fully_evaluated=6244, certificate_rejected=53760, completed=True))
        self.emit('candidate_summary', [dict(identity='full', qualified_improvement=True), dict(identity='pending')])
        self.emit('checker', [dict(identity='full', status='PASS')])
        self.emit('certificates', [dict(identity='cert', feasibility=None)])
        self.emit('certificate_checker', [dict(identity='cert', status='PASS')])
        result = prefix_counts(self.root)
        self.assertEqual((result['declared_candidates'], result['fully_evaluated'],
            result['fully_independently_verified'], result['certificate_rejected'],
            result['certificate_independently_verified'], result['unprocessed'], result['unknown']),
            (60004, 2, 1, 1, 1, 60001, 1))
        self.assertTrue(result['retained_baseline'])

    def test_only_unfinished_final_json_line_can_be_omitted(self):
        path = self.root/'partial.jsonl'
        path.write_text('{"identity":"finished"}\n{"identity":', encoding='utf8')
        self.assertEqual(list(durable_records(path)), [dict(identity='finished')])
        path.write_text('{"identity":\n{"identity":"finished"}\n', encoding='utf8')
        with self.assertRaises(json.JSONDecodeError):
            list(durable_records(path))

    def test_duplicate_full_and_certificate_identity_is_not_double_counted(self):
        self.emit('candidate_summary', [dict(identity='collision')])
        self.emit('certificates', [dict(identity='collision')])
        with self.assertRaisesRegex(EvidenceError, 'PREFIX_DUPLICATE_PROCESSED_IDENTITY'):
            prefix_counts(self.root)

    def test_shared_clock_stops_compute_while_sealing_reserve_remains(self):
        path = self.root/'lifecycle.json'
        write(path, dict(start_epoch=time.time()-6601, total_limit_seconds=7200, compute_limit_seconds=6600))
        life = Lifecycle(path)
        life.check()
        with self.assertRaises(BudgetExceeded):
            life.timeout()
        status = Status(); status.add('FAIL', 'matrix row mismatch'); status.add('BLOCKED', 'deadline')
        self.assertEqual((status.value, status.exit_code), ('FAIL', 1))
        self.assertEqual(classify(PermissionError('ROUND16_GUARD_VENDOR_EXECUTION')), 'FAIL')


if __name__ == '__main__':
    unittest.main()
