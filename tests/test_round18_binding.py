"""R18 profile separation, immutable old245 and executed-attempt provenance."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.round13.common import EvidenceError, fingerprint, read, record, write
from src.round18 import binding


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND18_TEST_ROOT'))
        self.root=Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def source(self,name,text='SAVED = True\n'):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(text,encoding='utf8')
        return dict(record(path),relative_path=name)

    def attempt(self):
        rows=[self.source('src/round18/consumer.py')]
        attempt=self.root/'work/round18/run/attempts/science_1'
        out=attempt/'output';out.mkdir(parents=True)
        write(attempt/'consumer_code.json',rows)
        with zipfile.ZipFile(attempt/'consumer_code.zip','w') as snapshot:
            snapshot.write(rows[0]['path'],rows[0]['relative_path'])
        result=dict(status='PASS',exit_code=0,attempt_id=attempt.name,
            job='science',consumer_identity=fingerprint(rows))
        write(out/'job_result.json',result);write(attempt/'supervised_result.json',result)
        command=dict(attempt_id=attempt.name,job='science',code_manifest=rows,output=str(out),
            command=[sys.executable,'-X','utf8','-B','-m','src.round18.worker','--work',
                str(attempt.parent.parent),'--out',str(out),'--job','science'],
            output_artifacts=binding.artifacts(out),python_exit_code=0,
            supervised_result_exit_code=0,timeout=False)
        write(attempt/'command_result.json',command)
        return attempt,rows,command

    def test_new_source_policy_is_confined_to_r18_without_path_aliases(self):
        for name in ['src/round18/checker.py','tests/test_round18_control.py',
                     'tools/export_round18.py','configs/round18.json','docs/round18.md']:
            self.assertTrue(binding.allowed_new(name))
        for name in ['src/round17/new.py','tests/test_round17_control.py','configs/round17.json',
                     'src/round18/../round17/new.py','G:/outside.py','src/round18\\..\\round17/new.py']:
            self.assertFalse(binding.allowed_new(name))

    def test_freeze_protects_all_245_old_bytes_and_records_r18_scope(self):
        cfg=read(binding.ROOT/'configs/round18.json')
        old=[self.source('src/prior/file_'+str(i)+'.py',str(i)+'\n') for i in range(245)]
        for name in ['src/round18/consumer.py','tools/run_round18.py','tools/export_round18.py',
                     'configs/round18.json','docs/round18.md']:
            self.source(name)
        work=self.root/'work/round18/run';work.mkdir(parents=True)
        write(work/'starting_code_manifest.json',old)
        meta=dict(anchor_identities={str(p):'synthetic-anchor-'+str(p) for p in [28,218,1801,2021]})
        changed=Path(old[0]['path']);changed.write_text('user changed\n',encoding='utf8')
        with patch.object(binding,'ROOT',self.root):
            with self.assertRaisesRegex(EvidenceError,'R17_SOURCE_BYTES_CHANGED'):
                binding.freeze(work,cfg,meta)
            self.assertEqual(changed.read_text(encoding='utf8'),'user changed\n')
            changed.write_text('0\n',encoding='utf8')
            rows=binding.freeze(work,cfg,meta)
            self.assertEqual(len(rows),250)
            policy=read(work/'frozen/change_policy.json')
            contract=read(work/'frozen/contract.json')
            self.assertEqual((policy['unchanged_prior_files'],policy['allowed_modified']),(245,[]))
            self.assertEqual((contract['profile'],contract['declared_candidates']),('ROUND18_V1',231066))
            self.assertEqual(contract['anchor_identities'],meta['anchor_identities'])
            self.assertEqual(contract['excluded_donor'],705)
            changed.write_text('later changed\n',encoding='utf8')
            with self.assertRaisesRegex(EvidenceError,'FROZEN_SOURCE_CHANGED'):
                binding.verify_sources(rows)

    def test_wrong_round_worker_and_attempt_identity_are_rejected(self):
        attempt,rows,original=self.attempt()
        with patch.object(binding,'ROOT',self.root):
            self.assertEqual(binding.verify_attempt(attempt,rows)['profile'],'ROUND18_V1')
            changed=copy.deepcopy(original);changed['command'][5]='src.round17.worker'
            write(attempt/'command_result.json',changed)
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_COMMAND_MISMATCH'):
                binding.verify_attempt(attempt,rows)
            changed=copy.deepcopy(original);changed['attempt_id']='another_science_attempt'
            write(attempt/'command_result.json',changed)
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_PATH_MISMATCH'):
                binding.verify_attempt(attempt,rows)

    def test_stale_source_or_snapshot_cannot_be_attached_to_new_attempt(self):
        attempt,rows,original=self.attempt()
        with patch.object(binding,'ROOT',self.root):
            write(attempt/'consumer_code.json',[])
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_CONSUMER_VERSION_MISMATCH'):
                binding.verify_attempt(attempt,rows)
            write(attempt/'consumer_code.json',rows)
            with zipfile.ZipFile(attempt/'consumer_code.zip','w') as snapshot:
                snapshot.writestr(rows[0]['relative_path'],'OTHER VERSION\n')
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_SNAPSHOT_BYTES'):
                binding.verify_attempt(attempt,rows)

    def test_output_set_and_supervised_return_code_are_bound(self):
        attempt,rows,original=self.attempt()
        with patch.object(binding,'ROOT',self.root):
            (attempt/'output/unlisted.json').write_text('{}\n',encoding='utf8')
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_OUTPUT_ARTIFACT_MISMATCH'):
                binding.verify_attempt(attempt,rows)
            (attempt/'output/unlisted.json').unlink()
            changed=copy.deepcopy(original);changed['supervised_result_exit_code']=2
            write(attempt/'command_result.json',changed)
            with self.assertRaisesRegex(EvidenceError,'ATTEMPT_SUPERVISED_RESULT_BINDING'):
                binding.verify_attempt(attempt,rows)


if __name__ == '__main__':
    unittest.main()
