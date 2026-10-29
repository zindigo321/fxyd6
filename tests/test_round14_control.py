"""Deadline, fail priority and round14 source/attempt boundary checks."""
import os
from pathlib import Path
import tempfile
import time
import unittest
import sys
import zipfile
from unittest.mock import patch
from src.round13.common import EvidenceError,write,record,fingerprint
from src.round14.control import Lifecycle,Status,BudgetExceeded,classify
from src.round14 import binding


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND14_TEST_ROOT'));self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def life(self,elapsed):
        path=self.root/'life.json';write(path,dict(start_epoch=time.time()-elapsed,total_limit_seconds=7200,compute_limit_seconds=6600));return Lifecycle(path)
    def test_running_child_timeout_respects_compute_reserve(self):
        life=self.life(6590);self.assertGreater(life.remaining(),600);self.assertGreater(life.timeout(),9);self.assertLessEqual(life.timeout(),10)
    def test_compute_expired_before_total_expired(self):
        life=self.life(6601);life.check()
        with self.assertRaises(BudgetExceeded):life.check(True)
    def test_total_expiry(self):
        with self.assertRaises(BudgetExceeded):self.life(7201).check()
    def test_fail_is_not_downgraded_by_timeout(self):
        s=Status();s.add('FAIL','wrong metrics');s.add('BLOCKED','timeout');self.assertEqual((s.value,s.exit_code),('FAIL',1))
    def test_guard_violation_is_fail(self):
        self.assertEqual(classify(PermissionError('ROUND14_GUARD_VENDOR_EXECUTION')),'FAIL')
    def test_missing_library_is_blocked(self):
        self.assertEqual(classify(FileNotFoundError('UNAVAILABLE_FROM_FROZEN_LIBRARY')),'BLOCKED')
    def test_round14_allowlist_is_narrow(self):
        for name in ['src/round14/run.py','tests/test_round14_x.py','configs/round14.json','tools/run_round14.py','docs/round14.md']:
            self.assertTrue(binding.allowed_new(name))
        for name in ['README.md','src/round13/x.py','tests/test_round13_x.py','configs/round15.json']:
            self.assertFalse(binding.allowed_new(name))
    def test_source_path_escape_rejected(self):
        row=dict(path=str(self.root/'outside.py'),relative_path='../outside.py',bytes=0,sha256='x')
        with patch.object(binding,'ROOT',self.root/'repo'):
            with self.assertRaisesRegex(EvidenceError,'SOURCE_PATH_ESCAPE'):binding.verify_sources([row])
    def test_changed_source_rejected(self):
        p=self.root/'x.py';p.write_text('x=1',encoding='utf8');row=dict(record(p),relative_path='x.py');p.write_text('x=2',encoding='utf8')
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'FROZEN_SOURCE_CHANGED'):binding.verify_sources([row])
    def test_case_colliding_sources_rejected(self):
        rows=[dict(relative_path='x.py'),dict(relative_path='X.py')]
        with self.assertRaisesRegex(EvidenceError,'DUPLICATE_SOURCE_PATH'):binding.verify_sources(rows)


class AttemptBindingTests(unittest.TestCase):
    setUp=ControlTests.setUp
    tearDown=ControlTests.tearDown
    def fixture(self):
        source=self.root/'source.py';source.write_text('x=1',encoding='utf8')
        rows=[dict(record(source),relative_path='source.py')]
        attempt=self.root/'work/attempts/a_science';out=attempt/'output';out.mkdir(parents=True)
        write(attempt/'consumer_code.json',rows)
        write(out/'job_result.json',dict(status='PASS',exit_code=0,job='science',attempt_id=attempt.name,consumer_identity=fingerprint(rows)))
        with zipfile.ZipFile(attempt/'consumer_code.zip','w') as z:z.write(source,'source.py')
        write(attempt/'supervised_result.json',__import__('src.round13.common',fromlist=['read']).read(out/'job_result.json'))
        command=dict(command=[sys.executable,'-X','utf8','-B','-m','src.round14.worker','--work',str(attempt.parent.parent),
            '--out',str(out),'--job','science'],code_manifest=rows,attempt_id=attempt.name,job='science',output=str(out),
            timeout=False,python_exit_code=0,supervised_result_exit_code=0,output_artifacts=binding.artifacts(out))
        write(attempt/'command_result.json',command)
        return attempt,rows,command
    def test_same_source_and_attempt_positive(self):
        attempt,rows,_=self.fixture()
        with patch.object(binding,'ROOT',self.root):self.assertEqual(binding.verify_attempt(attempt,rows)['status'],'PASS')
    def test_forged_command_module_rejected(self):
        attempt,rows,command=self.fixture();command['command'][5]='different.module';write(attempt/'command_result.json',command)
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_COMMAND_MISMATCH'):binding.verify_attempt(attempt,rows)
    def test_changed_attempt_id_rejected(self):
        attempt,rows,command=self.fixture();command['attempt_id']='other';write(attempt/'command_result.json',command)
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_PATH_MISMATCH'):binding.verify_attempt(attempt,rows)
    def test_forged_single_consumer_rejected(self):
        attempt,rows,command=self.fixture();forged=[dict(rows[0],sha256='0'*64)];write(attempt/'consumer_code.json',forged)
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_CONSUMER_VERSION_MISMATCH'):binding.verify_attempt(attempt,rows)
    def test_old_pass_new_source_rejected(self):
        attempt,rows,_=self.fixture();(self.root/'source.py').write_text('x=2',encoding='utf8')
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'FROZEN_SOURCE_CHANGED'):binding.verify_attempt(attempt,rows)
    def test_timed_out_attempt_not_accepted(self):
        attempt,rows,command=self.fixture();command['timeout']=True;write(attempt/'command_result.json',command)
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_INCOMPLETE_OR_UNKNOWN_JOB'):binding.verify_attempt(attempt,rows)
    def test_artifact_tamper_rejected(self):
        attempt,rows,_=self.fixture();write(attempt/'output/extra.json',{})
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_OUTPUT_ARTIFACT_MISMATCH'):binding.verify_attempt(attempt,rows)
    def test_snapshot_tamper_rejected(self):
        attempt,rows,_=self.fixture()
        with zipfile.ZipFile(attempt/'consumer_code.zip','w') as z:z.writestr('source.py','wrong')
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_SNAPSHOT_BYTES'):binding.verify_attempt(attempt,rows)
    def test_supervised_result_tamper_rejected(self):
        attempt,rows,_=self.fixture();write(attempt/'supervised_result.json',dict(status='FAIL',exit_code=1))
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_SUPERVISED_RESULT_BINDING'):binding.verify_attempt(attempt,rows)


if __name__=='__main__':unittest.main()
