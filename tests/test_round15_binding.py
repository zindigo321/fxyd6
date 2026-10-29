"""Source/profile, selected attempt and isolated-suite adapter boundaries."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from src.round13.common import EvidenceError, fingerprint, read, record, write
from src.round15 import binding, regression


class FixtureCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND15_TEST_ROOT'))
        self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()


class SourcePolicyTests(FixtureCase):
    def test_only_r15_additions_allowed(self):
        allowed = ['src/round15/worker.py', 'tests/test_round15_x.py', 'tools/run_round15.py',
                   'configs/round15.json', 'docs/round15.md']
        denied = ['src/round14/x.py', 'tests/test_round14_x.py', 'README.md', 'configs/round16.json',
                  'src/round15/../round14/x.py', '/src/round15/x.py']
        self.assertTrue(all(binding.allowed_new(name) for name in allowed))
        self.assertFalse(any(binding.allowed_new(name) for name in denied))

    def test_case_colliding_source_records_rejected(self):
        with self.assertRaisesRegex(EvidenceError, 'DUPLICATE_SOURCE_PATH'):
            binding.verify_sources([dict(relative_path='x.py'), dict(relative_path='X.py')])

    def prepare_freeze(self):
        work = self.root/'work/round15/run'; work.mkdir(parents=True)
        rows = []
        for index in range(185):
            p = self.root/f'src/prior/file{index:03d}.py'; p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f'VALUE={index}\n', encoding='utf8')
            rows.append(dict(record(p), relative_path=p.relative_to(self.root).as_posix()))
        write(work/'starting_code_manifest.json', dict(files=rows))
        for name in ['src/round15/new.py', 'tests/test_round15_new.py', 'tools/run_round15.py',
                     'configs/round15.json', 'docs/round15.md']:
            p = self.root/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('new\n', encoding='utf8')
        return work, rows

    def test_freeze_preserves_all185_and_snapshots_new_files(self):
        work, old = self.prepare_freeze()
        with patch.object(binding, 'ROOT', self.root):
            rows = binding.freeze(work, {}, dict(generator='two-swap'))
        self.assertEqual(len(rows), 190)
        self.assertEqual(read(work/'frozen/change_policy.json')['unchanged_prior_files'], 185)
        with zipfile.ZipFile(work/'frozen/consumer_code.zip') as z:
            self.assertEqual(set(z.namelist()), {row['relative_path'] for row in rows})
        self.assertEqual(read(work/'frozen/contract.json')['source_manifest_identity'], fingerprint(rows))

    def test_existing_file_change_rejected(self):
        work, old = self.prepare_freeze(); Path(old[0]['path']).write_text('changed', encoding='utf8')
        with patch.object(binding, 'ROOT', self.root):
            with self.assertRaisesRegex(EvidenceError, 'R14_SOURCE_BYTES_CHANGED'):
                binding.freeze(work, {}, {})

    def test_unauthorized_new_file_rejected(self):
        work, _ = self.prepare_freeze(); p=self.root/'src/round14/extra.py';p.parent.mkdir();p.write_text('bad')
        with patch.object(binding, 'ROOT', self.root):
            with self.assertRaisesRegex(EvidenceError, 'ADDITION_OUTSIDE_ROUND15'):
                binding.freeze(work, {}, {})


class AttemptTests(FixtureCase):
    def fixture(self):
        p=self.root/'source.py';p.write_text('VALUE=1\n',encoding='utf8')
        rows=[dict(record(p),relative_path='source.py')]
        attempt=self.root/'work/round15/run/attempts/actual_science';out=attempt/'output';out.mkdir(parents=True)
        write(attempt/'consumer_code.json',rows)
        with zipfile.ZipFile(attempt/'consumer_code.zip','w') as z:z.write(p,'source.py')
        result=dict(status='PASS',exit_code=0,job='science',attempt_id=attempt.name,consumer_identity=fingerprint(rows))
        write(out/'job_result.json',result);write(attempt/'supervised_result.json',result)
        command=dict(command=[sys.executable,'-X','utf8','-B','-m','src.round15.worker','--work',str(attempt.parent.parent),
            '--out',str(out),'--job','science'],code_manifest=rows,attempt_id=attempt.name,job='science',output=str(out),
            timeout=False,python_exit_code=0,supervised_result_exit_code=0,output_artifacts=binding.artifacts(out))
        write(attempt/'command_result.json',command)
        return attempt,rows,command

    def verify(self,attempt,rows):
        with patch.object(binding,'ROOT',self.root):return binding.verify_attempt(attempt,rows)

    def test_same_version_and_actual_attempt_pass(self):
        attempt,rows,_=self.fixture();self.assertEqual(self.verify(attempt,rows)['status'],'PASS')

    def test_old_pass_cannot_bind_changed_source(self):
        attempt,rows,_=self.fixture();(self.root/'source.py').write_text('VALUE=2\n')
        with self.assertRaisesRegex(EvidenceError,'FROZEN_SOURCE_CHANGED'):self.verify(attempt,rows)

    def test_wrong_attempt_rejected(self):
        attempt,rows,command=self.fixture();command['attempt_id']='other';write(attempt/'command_result.json',command)
        with self.assertRaisesRegex(EvidenceError,'ATTEMPT_PATH_MISMATCH'):self.verify(attempt,rows)

    def test_unapproved_command_module_rejected(self):
        attempt,rows,command=self.fixture();command['command'][5]='src.round14.worker';write(attempt/'command_result.json',command)
        with self.assertRaisesRegex(EvidenceError,'ATTEMPT_COMMAND_MISMATCH'):self.verify(attempt,rows)

    def test_single_consumer_record_forgery_rejected(self):
        attempt,rows,_=self.fixture();write(attempt/'consumer_code.json',[dict(rows[0],sha256='0'*64)])
        with self.assertRaisesRegex(EvidenceError,'ATTEMPT_CONSUMER_VERSION_MISMATCH'):self.verify(attempt,rows)

    def test_changed_output_set_rejected(self):
        attempt,rows,_=self.fixture();write(attempt/'output/extra.json',{})
        with self.assertRaisesRegex(EvidenceError,'ATTEMPT_OUTPUT_ARTIFACT_MISMATCH'):self.verify(attempt,rows)

    def test_snapshot_bytes_rejected(self):
        attempt,rows,_=self.fixture()
        with zipfile.ZipFile(attempt/'consumer_code.zip','w') as z:z.writestr('source.py','altered')
        with self.assertRaisesRegex(EvidenceError,'ATTEMPT_SNAPSHOT_BYTES'):self.verify(attempt,rows)

    def test_timeout_never_passes(self):
        attempt,rows,command=self.fixture();command['timeout']=True;write(attempt/'command_result.json',command)
        with self.assertRaisesRegex(EvidenceError,'ATTEMPT_NOT_COMPLETED_PASS'):self.verify(attempt,rows)

    def test_supervised_fail_cannot_bind_worker_pass(self):
        attempt,rows,_=self.fixture();write(attempt/'supervised_result.json',dict(status='FAIL',exit_code=1))
        with self.assertRaisesRegex(EvidenceError,'ATTEMPT_SUPERVISED_RESULT_BINDING'):self.verify(attempt,rows)


class RegressionAdapterTests(FixtureCase):
    def test_copy_mapping_detects_source_and_isolated_tamper(self):
        source=self.root/'source.py';source.write_text('A=1');row=dict(record(source),relative_path='source.py')
        repo=self.root/'copy';repo.mkdir();shutil.copyfile(source,repo/'source.py')
        self.assertEqual(len(regression.verify_mapping(self.root,repo,[row])),1)
        (repo/'source.py').write_text('A=2')
        with self.assertRaisesRegex(EvidenceError,'REGRESSION_COPY_VERSION_MISMATCH'):
            regression.verify_mapping(self.root,repo,[row])
        source.write_text('A=3')
        with self.assertRaisesRegex(EvidenceError,'REGRESSION_SOURCE_VERSION_MISMATCH'):
            regression.verify_mapping(self.root,repo,[row])

    def test_selection_adapter_selects_exact_initial_suite_only(self):
        log=self.root/'selection.json';calls=[];loader=unittest.defaultTestLoader;original=loader.discover
        def discover(start_dir,pattern='test*.py',top_level_dir=None):
            calls.append((start_dir,pattern,top_level_dir));return pattern
        try:
            with patch.object(loader,'discover',discover),patch.dict(sys.modules,{'guard_impl':SimpleNamespace(install=lambda:None)}),patch.dict(os.environ,{'ROUND15_SELECTION_LOG':str(log)}):
                exec(compile(regression.R14_SITE,'<controlled_round15_test_selector>','exec'),{})
                self.assertEqual(loader.discover('tests'),'test_round14*.py')
                self.assertEqual(loader.discover('tests'),'test*.py')
                self.assertEqual(loader.discover('other',pattern='explicit*.py'),'explicit*.py')
        finally:
            loader.discover=original
        self.assertEqual(read(log)['selected_pattern'],'test_round14*.py')
        self.assertEqual(len(calls),3)

    def test_test_id_binding_rejects_repeated_or_wrong_ids(self):
        first=self.root/'first.log';second=self.root/'second.log'
        first.write_text('test_a (mod.C.test_a) ... ok\n',encoding='utf8')
        second.write_text('test_b (mod.C.test_b) ... ok\n',encoding='utf8')
        with self.assertRaisesRegex(EvidenceError,'HISTORICAL_TEST_ID_SET_MISMATCH'):
            regression.verify_ids(first,second,1)
        first.write_text('test_a (mod.C.test_a) ... ok\ntest_a (mod.C.test_a) ... ok\n',encoding='utf8')
        with self.assertRaisesRegex(EvidenceError,'DUPLICATED_ACTUAL_TEST_IDS'):regression.test_ids(first)

    def test_test_id_parser_keeps_argparse_stderr_interleaving(self):
        log=self.root/'interleaved.log'
        log.write_text('test_a (mod.C.test_a) ... usage: test [-h]\nerror: unknown\nok\n',encoding='utf8')
        self.assertEqual(regression.test_ids(log),['mod.C.test_a'])


if __name__=='__main__':unittest.main()
