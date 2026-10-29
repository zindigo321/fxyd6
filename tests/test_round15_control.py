"""Shared deadline enforcement and durable-prefix accounting."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from src.round13.common import write
from src.round15.control import Lifecycle,BudgetExceeded,Status,classify
from src.round15.seal import prefix_counts


class DeadlineAndPrefix(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND15_TEST_ROOT'));self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_running_child_stops_before_seal_reserve(self):
        path=self.root/'life.json';write(path,dict(start_epoch=time.time()-6590,total_limit_seconds=7200,compute_limit_seconds=6600))
        life=Lifecycle(path);self.assertLessEqual(life.timeout(),10);self.assertGreater(life.remaining(),600)
    def test_compute_cutoff_is_earlier_than_total(self):
        path=self.root/'life.json';write(path,dict(start_epoch=time.time()-6601,total_limit_seconds=7200,compute_limit_seconds=6600))
        life=Lifecycle(path);life.check()
        with self.assertRaises(BudgetExceeded):life.check(True)
    def test_substantive_fail_dominates_later_timeout(self):
        result=Status();result.add('FAIL','wrong proof');result.add('BLOCKED','timeout');self.assertEqual((result.value,result.exit_code),('FAIL',1))
        self.assertEqual(classify(PermissionError('ROUND15_GUARD_VENDOR_EXECUTION')),'FAIL')
    def test_prefix_is_derived_from_durable_rows(self):
        write(self.root/'progress.json',dict(fully_evaluated=0))
        for name,rows in [('candidate_summary',[dict(identity='a',qualified_improvement=True),dict(identity='b',qualified_improvement=False)]),
                          ('checker',[dict(identity='a',status='PASS')]),('certificates',[dict(identity='c')]),('certificate_checker',[dict(identity='c',status='PASS')])]:
            (self.root/(name+'.jsonl')).write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf8')
        result=prefix_counts(self.root)
        self.assertEqual((result['fully_evaluated'],result['fully_independently_verified'],result['certificate_rejected'],result['certificate_independently_verified']),(2,1,1,1))
        self.assertEqual((result['unprocessed'],result['unknown'],result['qualified_count']),(187485,1,1))
    def test_empty_prefix_is_not_complete(self):
        result=prefix_counts(self.root);self.assertEqual(result['unprocessed'],187488);self.assertEqual(result['fully_evaluated'],0)


if __name__=='__main__':unittest.main()
