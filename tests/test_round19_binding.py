import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.round13.common import read, write, record, fingerprint
from src.round19 import binding, seal
from src.round19.regression import source_subset


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND19_TEST_ROOT'))
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_old268_preserved_and_subsets_have_exact_members(self):
        cfg=read(binding.ROOT/'configs/round19.json')
        rows=read(Path(cfg['r18_delivery'])/'sealed/frozen/consumer_code.json')
        self.assertEqual(len(rows),268)
        for count in [168,185,203,223,245,268]:
            chosen=source_subset(rows,count)
            self.assertEqual(len(chosen),count)
            self.assertTrue(set(r['relative_path'] for r in chosen)<=set(r['relative_path'] for r in rows))
        binding.verify_sources(rows)

    def test_source_content_tamper_rejected(self):
        p=self.root/'file.py';p.write_text('before',encoding='utf8')
        row=dict(record(p),relative_path='file.py')
        p.write_text('after',encoding='utf8')
        with patch.object(binding,'ROOT',self.root),self.assertRaisesRegex(ValueError,'FROZEN_SOURCE_CHANGED'):
            binding.verify_sources([row])

    def test_source_relative_escape_rejected(self):
        p=self.root/'file.py';p.write_text('a',encoding='utf8')
        row=dict(record(p),relative_path='../escape.py')
        with patch.object(binding,'ROOT',self.root),self.assertRaises(ValueError):
            binding.verify_sources([row])

    def test_source_same_count_duplicate_rejected(self):
        p=self.root/'a.py';p.write_text('a',encoding='utf8')
        a=dict(record(p),relative_path='a.py');b=dict(a,relative_path='A.py')
        with patch.object(binding,'ROOT',self.root),self.assertRaisesRegex(ValueError,'DUPLICATE_SOURCE_PATH'):
            binding.verify_sources([a,b])

    def test_wrong_attempt_consumer_binding_rejected(self):
        attempt=self.root/'attempts'/'one';attempt.mkdir(parents=True)
        write(attempt/'consumer_code.json',[{'wrong':'consumer'}]);write(attempt/'command_result.json',{'code_manifest':[]})
        with self.assertRaisesRegex(ValueError,'ATTEMPT_CONSUMER_VERSION_MISMATCH'):
            binding.verify_attempt(attempt,[])

    def test_allowed_scope_rejects_old_profiles_and_checkpoints(self):
        self.assertTrue(binding.allowed_new('src/round19/new.py'))
        self.assertFalse(binding.allowed_new('src/round18/new.py'))
        self.assertFalse(binding.allowed_new('checkpoints/round18/evidence.json'))
        self.assertFalse(binding.allowed_new('tests/nested/test_round19.py'))

    def test_final_partial_line_cannot_count_as_processed_record(self):
        p=self.root/'items.jsonl';p.write_text('{"identity":"ok"}\n{"identity":',encoding='utf8')
        self.assertEqual(list(seal.durable_records(p)),[{'identity':'ok'}])

    def test_middle_corruption_rejected(self):
        p=self.root/'items.jsonl';p.write_text('{bad}\n{}\n',encoding='utf8')
        with self.assertRaises(json.JSONDecodeError):list(seal.durable_records(p))

    def test_utf8_report_has_real_chinese_and_all_partitions(self):
        final=dict(status='BLOCKED',exit_code=2,optimization_outcome='PARTIAL_NOT_CONCLUDED',
            GAP_certificate_rejected=0,GAP_certificate_verified=0,T100_certificate_rejected=0,T100_certificate_verified=0,
            T90_certificate_rejected=0,T90_certificate_verified=0,fully_evaluated=0,fully_independently_verified=0,
            unprocessed=60004,unknown=0,qualified_for_round19=0,retained_R18_incumbent=True,lifecycle_elapsed_at_seal_s=12)
        text=seal.report_text(final,self.root)
        p=self.root/'report.md';p.write_text(text,encoding='utf8')
        self.assertIn('第十九轮',p.read_text(encoding='utf8'))
        self.assertNotIn('???',text)
        self.assertIn('| GAP | 0 | 0 |',text)


if __name__=='__main__':unittest.main()
