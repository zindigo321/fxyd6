import copy
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from src.round8.common import NORMALIZATION, apply_final_checks, file_record, identities, no_fresh_native, preserve, read, separate_paths, text, text_hashes, write
from src.round8.binding import native_equivalence
from src.round8.science import deep_diff, endpoint_sweep


class Round8Tests(unittest.TestCase):
    def test_raw_hash_never_replaced_by_text_hash(self):
        a=text_hashes(b'hello\r\n');b=text_hashes(b'hello\n')
        self.assertEqual(a['normalized_text_sha256'],b['normalized_text_sha256'])
        self.assertNotEqual(a['raw_file_sha256'],b['raw_file_sha256'])
        self.assertFalse(preserve(dict(sha256=a['raw_file_sha256'],bytes=a['raw_bytes']),dict(sha256=b['raw_file_sha256'],bytes=b['raw_bytes'])))

    def test_normalization_preserves_bom_lone_cr_and_terminal_newline(self):
        a=text_hashes(b'\xef\xbb\xbfA\r\nB\r')
        self.assertTrue(a['bom']);self.assertEqual(a['lone_cr'],1)
        for other in [b'A\nB\r',b'\xef\xbb\xbfA\nB',b'\xef\xbb\xbfA\nB\r\n']:
            self.assertNotEqual(a['normalized_text_sha256'],text_hashes(other)['normalized_text_sha256'])

    def test_wrong_hash_algorithm_label_rejected(self):
        with self.assertRaisesRegex(ValueError,'HASH_ALGORITHM_LABEL'):text_hashes(b'A\r\n','strip whitespace')

    def test_subject_validator_separation(self):
        s=dict(run_id='S',code_sha256='s',config_sha256='c',input_sha256='i');k=dict(s,run_id='K',code_sha256='k')
        self.assertEqual(identities(s,k)['subject'],s)
        with self.assertRaisesRegex(ValueError,'SUBJECT_VALIDATOR_MIXED'):identities(s,s)

    def test_function_equal_does_not_hide_global_or_import_or_dispatch_change(self):
        before={'src/p.py':b'from old import Model\nX=1\ndef f(x=Model): return x(X)\n'}
        for blob in [before['src/p.py'].replace(b'X=1',b'X=2'),before['src/p.py'].replace(b'old',b'new'),before['src/p.py'].replace(b'x=Model',b'x=Other')]:
            with self.subTest(blob=blob):self.assertEqual(native_equivalence(before,{'src/p.py':blob})['status'],'BLOCKED')

    def test_unreviewed_added_native_module_blocks(self):
        self.assertEqual(native_equivalence({'src/a.py':b'x=1'},{'src/a.py':b'x=1','src/hook.py':b'x=2'},allow_new=True)['status'],'BLOCKED')

    def test_output_source_overlap_rejected(self):
        base=Path(tempfile.gettempdir())/'round8-path-test'
        with self.assertRaisesRegex(ValueError,'OUTPUT_SOURCE_OVERLAP'):separate_paths(base/'s',base/'v',base/'s/out',base/'work')

    def test_fresh_claim_rejected(self):
        valid=dict(fresh_native_validation_performed=False,round8_native_activation_count=0,native_evidence_origin_run_id='S',subject_run_id='S',validator_run_id='K')
        self.assertTrue(no_fresh_native(valid))
        for key,value in [('fresh_native_validation_performed',True),('round8_native_activation_count',1),('native_evidence_origin_run_id','K')]:
            self.assertFalse(no_fresh_native(dict(valid,**{key:value})))

    def test_independent_sweep_keeps_unvisited_and_single_visit_points(self):
        points=[dict(point_id=x) for x in ['a','b','c']]
        events=[dict(record_id=str(i),point_id=p,sat_id=s,start_epsec=a,stop_epsec=b) for i,(p,s,a,b) in enumerate([('a','x',1,2),('a','y',2,3),('a','z',5,6),('b','x',1,2)])]
        result=endpoint_sweep(points,events,[0,10])
        self.assertEqual((result['denominator'],result['covered_points'],result['gap_count'],result['insufficient_access_points']),(3,2,1,2))
        self.assertEqual(result['conditional_mean_gap_s'],2)
        self.assertTrue(result['phenomena']['natural_overlap_or_touch'])

    def test_parameter_comparison_rejects_added_keys_and_list_truncation(self):
        self.assertTrue(deep_diff(dict(a=[1,2]),dict(a=[1])))
        self.assertTrue(deep_diff(dict(a=1),dict(a=1,b=2)))
        self.assertFalse(deep_diff(dict(a=[1.,2.]),dict(a=[1.,2.+1e-10])))

    def test_final_delivery_failure_changes_summary_and_exit(self):
        from tools.run_round8 import seal
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            summary=dict(offline_acceptance='PASS',exit_code=0,checks={'science':dict(status='PASS')})
            command=dict(exit_code=0,worker_exit_code=0)
            def report(folder,result,cmd):
                text(folder/'audit_report.md','原生证据来自未受影响的历史科学运行S' if result['offline_acceptance']=='PASS' else '复合离线验收未通过')
            with patch('src.round8.validate.report',report),patch('tools.run_round8.delivery',side_effect=[dict(status='FAIL'),dict(status='PASS')]):
                self.assertEqual(seal(out,summary,command),1)
            self.assertEqual(read(out/'final_status.json')['offline_acceptance'],'FAIL')
            self.assertEqual(read(out/'command_result.json')['exit_code'],1)
            self.assertEqual(read(out/'command_result.json')['validator_worker_exit_code'],0)

    def test_invalid_utf8_delivery_fails_with_successful_science(self):
        from tools.run_round8 import seal
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'invalid.log').write_bytes(b'\xff')
            summary=dict(offline_acceptance='PASS',exit_code=0,checks={'science':dict(status='PASS')})
            command=dict(exit_code=0,worker_exit_code=0)
            def report(folder,result,cmd):
                text(folder/'audit_report.md','原生证据来自未受影响的历史科学运行S' if result['offline_acceptance']=='PASS' else '复合离线验收未通过')
            with patch('src.round8.validate.report',report):self.assertEqual(seal(out,summary,command),1)
            self.assertEqual(read(out/'final_status.json')['checks']['encoding_readback']['status'],'FAIL')
            self.assertEqual(read(out/'delivery_verification.json')['status'],'PASS')

    def test_final_gate_does_not_erase_blocked_science(self):
        summary=dict(checks={'source':dict(status='BLOCKED')})
        apply_final_checks(summary,{'encoding':dict(status='PASS')})
        self.assertEqual((summary['offline_acceptance'],summary['exit_code']),('BLOCKED',1))

    def test_successful_seal_records_hashes_of_final_status_and_report(self):
        from tools.run_round8 import seal
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            summary=dict(offline_acceptance='PASS',exit_code=0,checks={'science':dict(status='PASS')})
            command=dict(exit_code=0,worker_exit_code=0)
            def report(folder,result,cmd):
                text(folder/'audit_report.md','原生证据来自未受影响的历史科学运行S'+str(result['checks']))
            with patch('src.round8.validate.report',report):self.assertEqual(seal(out,summary,command),0)
            for row in read(out/'encoding_audit.json')['files']:
                self.assertEqual(file_record(out/row['path'])['sha256'],row['sha256'],row['path'])
            for row in read(out/'artifact_manifest.json')['files']:
                self.assertEqual(file_record(row['path'])['sha256'],row['sha256'],row['path'])

    def test_optional_audit_directory_is_not_critical_input(self):
        from src.round8.manifests import plan
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);s=base/'S';v=base/'V';baseline=base/'baseline';out=base/'out'
            baseline.mkdir();out.mkdir()
            for folder in (s,v):
                for name in ['input_manifest.json','artifact_manifest.json','log_manifest.json']:write(folder/name,dict(files=[]))
            write(s/'benchmarks/cold_old/experiment.json',dict(old_dependency_closure=[]))
            write(s/'old_snapshot_reference.json',dict(source=str(base/'old.zip')))
            result=plan(s,v,baseline,base/'missing_optional',out)
            self.assertEqual(result['optional_reference_paths'],[])
            self.assertTrue(result['optional_reference_error'])
            self.assertFalse(any('missing_optional' in p for p in result['direct_paths']))

    def test_noncritical_fixture_byte_mismatch_is_not_permission_exception(self):
        from src.round8.manifests import audit,evidence_class
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);p=base/'tests/cases/test_sample/evidence.json';write(p,{'x':1})
            row=dict(file_record(p),owner='S',manifest='input_manifest.json',classification=evidence_class(p))
            write(p,{'x':2});out=base/'out';out.mkdir()
            result,_=audit(dict(references=[row],direct_paths=[]),out)
            self.assertEqual(result['status'],'FAIL')
            self.assertEqual(result['altered_references'][0]['status'],'MISMATCH')

    def test_noncritical_permission_denial_remains_unverified(self):
        from src.round8.manifests import audit
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);p=base/'fixture.json';write(p,{'x':1})
            row=dict(file_record(p),owner='S',manifest='input_manifest.json',classification='NONCRITICAL_HISTORICAL_UNITTEST_FIXTURE')
            with patch('src.round8.manifests.file_record',side_effect=PermissionError('fixture')):
                result,_=audit(dict(references=[row],direct_paths=[]),base)
            self.assertEqual(result['status'],'PASS')
            self.assertEqual(result['full_historical_artifact_audit_status'],'PARTIAL')
            self.assertEqual(result['files'][0]['status'],'UNREADABLE')


if __name__=='__main__':unittest.main()
