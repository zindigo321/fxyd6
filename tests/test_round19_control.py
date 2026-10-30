"""ROUND19 preparation-inclusive cutoffs and fail-dominant results."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src.round13.common import EvidenceError, read, write
from src.round19 import control


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND19_TEST_ROOT'))
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def clock(self,offset=6590.):
        record_epoch = 10000.
        path = self.root/'lifecycle.json'
        effective = record_epoch-offset
        write(path,dict(record_epoch=record_epoch,preparation_offset_seconds=offset,
            effective_start_epoch=effective,start_epoch=effective,start_epoch_already_includes_preparation=True,
            compute_limit_seconds=6600,total_limit_seconds=7200))
        return path

    def test_offset_consumes_real_parent_timeout_and_is_not_charged_twice(self):
        path = self.clock()
        with patch.object(control.time,'time',return_value=10000.), patch.object(control.time,'monotonic',return_value=500.):
            life = control.Lifecycle(path)
            self.assertEqual((life.elapsed(),life.remaining(),life.timeout()),(6590.,610.,10.))
        with patch.object(control.time,'time',return_value=20000.), patch.object(control.time,'monotonic',return_value=501.):
            self.assertEqual(life.elapsed(),6591.)
            self.assertEqual(life.timeout(),9.)

    def test_compute_and_total_deadlines_share_one_start_with_600s_reserve(self):
        path = self.clock(6600.)
        with patch.object(control.time,'time',return_value=10000.), patch.object(control.time,'monotonic',return_value=500.):
            life = control.Lifecycle(path)
            self.assertEqual(life.remaining(),600.)
            life.check(False)
            with self.assertRaisesRegex(control.BudgetExceeded,'ROUND19_COMPUTE_DEADLINE'):
                life.timeout()
        with patch.object(control.time,'monotonic',return_value=1100.):
            with self.assertRaisesRegex(control.BudgetExceeded,'ROUND19_TOTAL_DEADLINE'):
                life.check(False)

    def test_ambiguous_clock_metadata_and_altered_limits_rejected(self):
        path = self.clock(); original = read(path)
        for changes in [dict(start_epoch=10000.),dict(effective_start_epoch=3400.),
            dict(preparation_offset_seconds=-1.),dict(start_epoch_already_includes_preparation=False),
            dict(compute_limit_seconds=6599),dict(total_limit_seconds=7201)]:
            write(path,dict(original,**changes))
            with self.assertRaises(EvidenceError):
                control.Lifecycle(path)

    def test_fail_cannot_be_downgraded_by_later_timeout(self):
        state = control.Status()
        for level in ['BLOCKED','FAIL','PASS','BLOCKED']:
            state.add(level,'case')
        self.assertEqual((state.value,state.exit_code),('FAIL',1))
        self.assertEqual(control.classify(PermissionError('ROUND19_GUARD_NETWORK')),'FAIL')
        self.assertEqual(control.classify(subprocess.TimeoutExpired(['python'],1)),'BLOCKED')


if __name__ == '__main__':
    unittest.main()
