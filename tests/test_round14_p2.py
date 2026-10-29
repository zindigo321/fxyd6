"""Live R13 fixes, kept separate from the unchanged 202 historical tests."""
import copy
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from src.round13 import run
from src.round13.common import EvidenceError, fingerprint, read, record, sha, write
from src.round13.seal import verify_seal, verify_selected_attempts


class TempCase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND14_TEST_ROOT'))
        self.root=Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()


class SealedEntryTests(TempCase):
    def setUp(self):
        super().setUp()
        self.work=self.root/'work/round13/history'
        (self.work/'delivery').mkdir(parents=True)
        (self.work/'delivery/receipt.json').write_text('{}',encoding='utf8')

    def call(self,extra):
        with patch.object(run,'ROOT',self.root),patch.object(run,'ACTIVE_WORK',None),patch.object(sys,'argv',['run_round13.py','--work',str(self.work),*extra]),patch('src.round13.seal.verify_seal',return_value={'status':'PASS','exit_code':0}) as verify:
            result=run.main()
            self.assertEqual(result,0)
            verify.assert_called_once()

    def denied(self,extra,reason='SEALED_WORK_NEW_EVALUATION_REQUIRES_NEW_RUN'):
        with patch.object(run,'ROOT',self.root),patch.object(run,'ACTIVE_WORK',None),patch.object(sys,'argv',['run_round13.py','--work',str(self.work),*extra]),patch('src.round13.seal.verify_seal') as verify:
            with self.assertRaisesRegex(EvidenceError,reason):run.main()
            verify.assert_not_called()

    def test_plain_historical_reentry_uses_argparse_default(self):
        self.call([])

    def test_explicit_evaluate_existing_requires_new_run(self):
        self.denied(['--mode','evaluate-existing','--case','team_competition_N28'])

    def test_missing_request_is_not_old_pass(self):
        self.denied(['--request',str(self.root/'missing-request.json')])

    def test_changed_case_is_not_old_pass(self):
        self.denied(['--case','different-case'])

    def test_incompatible_fov_is_not_old_pass(self):
        request=self.root/'narrow.json';write(request,{'fov_half_deg':[0.001622,0.81]})
        self.denied(['--request',str(request)])

    def test_explicit_all_is_a_new_evaluation(self):
        self.denied(['--mode=all'])

    def test_abbreviated_request_cannot_bypass_explicit_argument_gate(self):
        with patch.object(run,'ROOT',self.root),patch.object(run,'ACTIVE_WORK',None),patch.object(sys,'argv',['run_round13.py','--work',str(self.work),'--req','missing.json']),patch('src.round13.seal.verify_seal') as verify:
            with self.assertRaises(SystemExit) as stopped:run.main()
            self.assertEqual(stopped.exception.code,2)
            verify.assert_not_called()

    def test_recheck_and_revision_are_new_operations(self):
        for extra in [['--mode','check'],['--main-out','other'],['--review-revision'],['--seal-dir','other']]:
            with self.subTest(extra=extra):self.denied(extra)

    def test_explicit_verify_seal_positive(self):
        self.call(['--mode','verify-seal','--seal-dir',str(self.work/'delivery')])

    def test_verify_seal_cannot_swallow_request(self):
        self.denied(['--mode','verify-seal','--seal-dir',str(self.work/'delivery'),'--request','missing.json'],'VERIFY_SEAL_NEW_EVALUATION_REQUIRES_NEW_RUN')


class SelectedAttemptBindingTests(TempCase):
    def setUp(self):
        super().setUp()
        self.work=self.root/'work/round13/research'
        self.code=self.root/'src/round13/example.py';self.code.parent.mkdir(parents=True)
        self.code.write_text('VALUE = 1\n',encoding='utf8')
        self.manifest=[record(self.code)]
        self.selections={}
        for key in ['main','check','tests','guards','legacy']:
            job='replay' if key=='main' else key
            attempt=self.work/'attempts'/('20260101_'+job+'_abc123')
            out=attempt/'output';out.mkdir(parents=True)
            write(attempt/'consumer_code.json',self.manifest)
            with zipfile.ZipFile(attempt/'consumer_code.zip','w') as z:
                z.write(self.code,'src/round13/example.py')
            result={'status':'PASS','exit_code':0}
            write(out/'job_result.json',result);write(attempt/'supervised_result.json',result)
            (out/'data.txt').write_text(key,encoding='utf8')
            if key=='main':write(out/'results.json',{'case':{'consumer_code_identity':fingerprint(self.manifest)}})
            argv=[sys.executable,'-X','utf8','-B','-m','src.round13.worker','--work',str(self.work),'--out',str(out),'--job',job]
            if key=='check':argv+=['--main-out',self.selections['main']['path']]
            command={'binding_profile':'round13-selected-attempt-v2','attempt_id':attempt.name,'job':job,'output_directory':str(out),
                     'command':argv,'code_manifest':copy.deepcopy(self.manifest),'python_exit_code':0,'timeout':False,
                     'output_manifest':[record(p) for p in sorted(out.rglob('*')) if p.is_file()]}
            write(attempt/'command_result.json',command)
            self.selections[key]=run.selected_attempt(out)

    def check(self,manifest=None):
        with patch.object(run,'ROOT',self.root):
            return verify_selected_attempts(self.work,self.selections,self.manifest if manifest is None else manifest)

    def command(self,key):
        return Path(self.selections[key]['path']).parent/'command_result.json'

    def refresh_command(self,key,command):
        write(self.command(key),command)
        self.selections[key]['command_result_sha256']=sha(self.command(key))

    def test_same_version_positive_all_five_jobs(self):
        result=self.check()
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(len(result['selected_attempts']),5)

    def test_old_pass_plus_new_source_rejected(self):
        self.code.write_text('VALUE = 2\n',encoding='utf8')
        with self.assertRaisesRegex(EvidenceError,'SEAL_CONSUMER_VERSION_MISMATCH'):self.check([record(self.code)])

    def test_replaced_attempt_path_rejected(self):
        self.selections['tests']['path']=self.selections['guards']['path']
        with self.assertRaisesRegex(EvidenceError,'SEAL_ATTEMPT_ID'):self.check()

    def test_replaced_attempt_command_id_rejected(self):
        command=read(self.command('tests'));command['attempt_id']='different-attempt'
        self.refresh_command('tests',command)
        with self.assertRaisesRegex(EvidenceError,'SEAL_COMMAND_ATTEMPT'):self.check()

    def test_one_forged_consumer_manifest_rejected(self):
        path=Path(self.selections['tests']['path']).parent/'consumer_code.json'
        forged=read(path);forged[0]['sha256']='0'*64;write(path,forged)
        with self.assertRaisesRegex(EvidenceError,'SEAL_CONSUMER_VERSION_MISMATCH'):self.check()

    def test_one_forged_command_manifest_rejected(self):
        command=read(self.command('tests'));command['code_manifest'][0]['bytes']+=1
        self.refresh_command('tests',command)
        with self.assertRaisesRegex(EvidenceError,'SEAL_CONSUMER_VERSION_MISMATCH'):self.check()

    def test_wrong_command_rejected(self):
        command=read(self.command('tests'));command['command'][-1]='guards'
        self.refresh_command('tests',command)
        with self.assertRaisesRegex(EvidenceError,'SEAL_COMMAND_MISMATCH'):self.check()

    def test_forged_snapshot_rejected(self):
        path=Path(self.selections['tests']['path']).parent/'consumer_code.zip'
        with zipfile.ZipFile(path,'w') as z:z.writestr('src/round13/example.py','VALUE = 9\n')
        with self.assertRaisesRegex(EvidenceError,'SEAL_CONSUMER_SNAPSHOT_BYTES'):self.check()

    def test_changed_output_rejected(self):
        (Path(self.selections['tests']['path'])/'data.txt').write_text('forged',encoding='utf8')
        with self.assertRaisesRegex(EvidenceError,'SEAL_OUTPUT_BYTES_MISMATCH'):self.check()

    def test_unlisted_output_rejected(self):
        (Path(self.selections['tests']['path'])/'extra.txt').write_text('extra',encoding='utf8')
        with self.assertRaisesRegex(EvidenceError,'SEAL_OUTPUT_MEMBER_SET'):self.check()

    def test_changed_result_rejected(self):
        write(Path(self.selections['tests']['path'])/'job_result.json',{'status':'FAIL','exit_code':1})
        with self.assertRaisesRegex(EvidenceError,'SEAL_SELECTED_ATTEMPT_DIGEST'):self.check()

    def test_wrong_main_consumer_identity_rejected(self):
        out=Path(self.selections['main']['path']);write(out/'results.json',{'case':{'consumer_code_identity':'forged'}})
        command=read(self.command('main'));command['output_manifest']=[record(p) for p in sorted(out.rglob('*')) if p.is_file()]
        self.refresh_command('main',command)
        with self.assertRaisesRegex(EvidenceError,'SEAL_MAIN_CONSUMER_IDENTITY'):self.check()

    def test_wrong_supervised_result_rejected(self):
        write(Path(self.selections['tests']['path']).parent/'supervised_result.json',{'status':'FAIL','exit_code':1})
        with self.assertRaisesRegex(EvidenceError,'SEAL_SUPERVISED_RESULT_MISMATCH'):self.check()

    def test_source_changed_after_manifest_rejected(self):
        self.code.write_text('VALUE = 3\n',encoding='utf8')
        with self.assertRaisesRegex(EvidenceError,'SEAL_FINAL_CODE_BYTES'):self.check()


class HistoricalSealCompatibilityTests(unittest.TestCase):
    def test_k13_uses_historical_profile_without_future_fields(self):
        folder=Path('G:/gpt-file/Codex/outputs/bd-fmb/round13/20261027T093702_offline/sealed')
        self.assertEqual(sha(folder/'artifact_manifest.json'),'de6b21246d76f034eff2ba6df82671f33fd225bf56c0834975713d064256c87e')
        result=verify_seal(folder)
        self.assertEqual((result['status'],result['exit_code'],result['verified_files']),('PASS',0,203))
        self.assertEqual(result['consumer_binding_profile'],'round13-historical-v1')
        self.assertFalse(result['reexecuted'])


class InvokeBindingIntegrationTests(TempCase):
    def test_real_coordinator_metadata_binds_controlled_synthetic_jobs(self):
        code=self.root/'src/round13/example.py';code.parent.mkdir(parents=True)
        code.write_text('VALUE = 1\n',encoding='utf8')
        work=self.root/'work/round13/research';work.mkdir(parents=True)
        life=SimpleNamespace(check=lambda:None,remaining=lambda:60,elapsed=lambda:0)
        def synthetic_worker(argv,**kwargs):
            # Exercise the real coordinator writes without creating a child process.
            out=Path(argv[argv.index('--out')+1]);out.mkdir()
            write(out/'job_result.json',{'status':'PASS','exit_code':0})
            if argv[argv.index('--job')+1]=='replay':
                write(out/'results.json',{'case':{'consumer_code_identity':fingerprint(read(out.parent/'consumer_code.json'))}})
            return SimpleNamespace(returncode=0)
        selections={}
        with patch.object(run,'ROOT',self.root),patch.object(run,'Lifecycle',return_value=life),patch.object(run,'code_files',return_value=[code]),patch.object(run.subprocess,'run',side_effect=synthetic_worker):
            for key in ['main','check','tests','guards','legacy']:
                extra=['--main-out',selections['main']['path']] if key=='check' else []
                out,result=run.invoke(work,'replay' if key=='main' else key,extra)
                self.assertEqual(result['exit_code'],0)
                selections[key]=run.selected_attempt(out)
            bound=verify_selected_attempts(work,selections,[record(code)])
        self.assertEqual(bound['status'],'PASS')
        self.assertEqual(len(bound['selected_attempts']),5)


if __name__=='__main__':
    unittest.main()
