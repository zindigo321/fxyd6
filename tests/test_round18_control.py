"""Preparation-inclusive deadlines at the actual parent invocation boundary."""
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from src.round13.common import EvidenceError, fingerprint, read, record, write
from src.round18 import binding, control, run, supervise


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND18_TEST_ROOT'))
        self.root=Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def clock(self, offset=6590., record_epoch=10000.):
        path=self.root/'lifecycle.json'
        effective=record_epoch-offset
        write(path,dict(record_epoch=record_epoch,preparation_offset_seconds=offset,
            effective_start_epoch=effective,start_epoch=effective,
            start_epoch_already_includes_preparation=True,
            compute_limit_seconds=6600,total_limit_seconds=7200))
        return path

    def test_preparation_offset_reduces_the_timeout_passed_to_parent_supervision(self):
        self.clock()
        source=self.root/'src/round18/consumer.py';source.parent.mkdir(parents=True)
        source.write_text('FROZEN = True\n',encoding='utf8')
        rows=[dict(record(source),relative_path='src/round18/consumer.py')]
        frozen=self.root/'frozen';frozen.mkdir()
        with zipfile.ZipFile(frozen/'consumer_code.zip','w') as snapshot:
            snapshot.write(source,rows[0]['relative_path'])
        received=[]
        def parent_boundary(argv,**kwargs):
            received.append(kwargs['timeout'])
            out=Path(argv[argv.index('--out')+1]);out.mkdir()
            write(out/'job_result.json',dict(status='PASS',exit_code=0,
                consumer_identity=fingerprint(rows),attempt_id=out.parent.name,job='tests'))
            return SimpleNamespace(returncode=0)
        with patch.object(run,'ROOT',self.root),patch.object(binding,'ROOT',self.root), \
             patch.object(supervise,'run',side_effect=parent_boundary), \
             patch.object(control.time,'time',return_value=10000.), \
             patch.object(control.time,'monotonic',return_value=500.):
            attempt,result=run.invoke(self.root,'tests',rows)
        self.assertEqual(received,[10.])
        self.assertEqual(result['exit_code'],0)
        self.assertEqual(read(attempt/'command_result.json')['enforced_timeout_s'],10.)

    def test_effective_start_is_not_charged_twice_and_monotonic_clock_ignores_wall_jump(self):
        path=self.clock()
        with patch.object(control.time,'time',return_value=10000.), \
             patch.object(control.time,'monotonic',return_value=500.):
            life=control.Lifecycle(path)
            self.assertEqual((life.elapsed(),life.remaining(),life.timeout()),(6590.,610.,10.))
        with patch.object(control.time,'time',return_value=20000.), \
             patch.object(control.time,'monotonic',return_value=501.):
            self.assertEqual(life.elapsed(),6591.)
            self.assertEqual(life.timeout(),9.)

    def test_6600_compute_cutoff_keeps_600_sealing_seconds_then_7200_stops_total(self):
        path=self.clock(offset=6600.)
        with patch.object(control.time,'time',return_value=10000.), \
             patch.object(control.time,'monotonic',return_value=500.):
            life=control.Lifecycle(path)
            life.check()
            self.assertEqual(life.remaining(),600.)
            with self.assertRaisesRegex(control.BudgetExceeded,'ROUND18_COMPUTE_DEADLINE'):
                life.timeout()
        with patch.object(control.time,'monotonic',return_value=1100.):
            with self.assertRaisesRegex(control.BudgetExceeded,'ROUND18_TOTAL_DEADLINE'):
                life.check()

    def test_ambiguous_or_double_charge_clock_metadata_is_rejected(self):
        path=self.clock();original=read(path)
        for changes in [dict(start_epoch=10000.),dict(effective_start_epoch=3400.),
                        dict(preparation_offset_seconds=-1.),dict(start_epoch_already_includes_preparation=False)]:
            write(path,dict(original,**changes))
            with self.assertRaises(EvidenceError):
                control.Lifecycle(path)

    def test_fail_dominates_budget_timeout_and_guard_violation_is_fail(self):
        state=control.Status()
        state.add('BLOCKED','deadline');state.add('FAIL','changed source');state.add('PASS','later job')
        state.add('BLOCKED','export reserve exhausted')
        self.assertEqual((state.value,state.exit_code),('FAIL',1))
        self.assertEqual(control.classify(PermissionError('ROUND18_GUARD_VENDOR_EXECUTION')),'FAIL')
        self.assertEqual(control.classify(subprocess.TimeoutExpired(['python'],1)),'BLOCKED')


if __name__ == '__main__':
    unittest.main()
