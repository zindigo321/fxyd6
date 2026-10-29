"""ROUND17 deadline, durable-prefix and immutable regression selection tests."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from src.round13.common import EvidenceError, write
from src.round17.control import Lifecycle, BudgetExceeded, Status, classify
from src.round17 import regression


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND17_TEST_ROOT'))
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_one_shared_clock_stops_compute_and_preserves_sealing_reserve(self):
        path = self.root/'lifecycle.json'
        write(path, dict(start_epoch=time.time()-6601, total_limit_seconds=7200, compute_limit_seconds=6600))
        life = Lifecycle(path)
        life.check()
        self.assertGreater(life.remaining(), 590)
        with self.assertRaises(BudgetExceeded):
            life.timeout()

    def test_substantive_fail_survives_later_deadline(self):
        state = Status(); state.add('FAIL', 'source row differs'); state.add('BLOCKED', 'shared deadline')
        self.assertEqual((state.value, state.exit_code), ('FAIL', 1))
        self.assertEqual(classify(PermissionError('ROUND17_GUARD_VENDOR_EXECUTION')), 'FAIL')
        self.assertEqual(classify(FileNotFoundError('input evidence missing')), 'BLOCKED')

    def test_historical_subsets_keep_exact_168_185_203_223_versions(self):
        rows = [dict(path=str(self.root/f'src/prior/f{i}.py'), relative_path=f'src/prior/f{i}.py') for i in range(168)]
        for number, count in [(14,17),(15,18),(16,20)]:
            rows += [dict(path=str(self.root/f'src/round{number}/f{i}.py'), relative_path=f'src/round{number}/f{i}.py') for i in range(count)]
        for count in [168,185,203,223]:
            self.assertEqual(regression.source_subset(rows, count, self.root), rows[:count])
        with self.assertRaisesRegex(EvidenceError, 'REGRESSION_SUBSET223_COUNT'):
            regression.source_subset(rows[:-1], 223, self.root)

    def test_discovery_adapter_selects_r16_without_rewriting_tests(self):
        adapter = regression.suite_adapter('test_round16*.py')
        self.assertIn("'test_round16*.py'", adapter)
        self.assertIn('test_files_modified=False', adapter)
        with self.assertRaisesRegex(EvidenceError, 'REGRESSION_SELECTION_PATTERN'):
            regression.suite_adapter('test*.py')

    def test_only_final_unfinished_jsonl_line_is_omitted(self):
        from src.round17.seal import durable_records
        path = self.root/'prefix.jsonl'
        path.write_text('{"identity":"complete"}\n{"identity":', encoding='utf8')
        self.assertEqual(list(durable_records(path)), [dict(identity='complete')])
        path.write_text('{"identity":\n{"identity":"complete"}\n', encoding='utf8')
        with self.assertRaises(json.JSONDecodeError):
            list(durable_records(path))
        path.write_text('{"identity":\n', encoding='utf8')
        with self.assertRaises(json.JSONDecodeError):
            list(durable_records(path))

    def test_duplicate_processed_identity_is_not_a_completed_prefix(self):
        from src.round17.seal import prefix_counts
        item = dict(identity='same', ordinal=0, partition='T100',
                    processing_state='T100_CERTIFICATE_REJECTED_AND_INDEPENDENTLY_VERIFIED')
        (self.root/'ledger.jsonl').write_text(json.dumps(item)+'\n'+json.dumps(item)+'\n', encoding='utf8')
        with self.assertRaises((EvidenceError, ValueError)):
            prefix_counts(self.root)


if __name__ == '__main__':unittest.main()
