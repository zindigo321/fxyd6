import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from src.round8.common import read,text,file_record
from tools.run_round9 import seal,verify_delivery

class Round9DeliveryTests(unittest.TestCase):
    def prepare(self,out):
        summary=dict(checks={'science':dict(status='PASS')})
        command=dict(exit_code=0)
        def report(folder,result,cmd):text(folder/'audit_report.md','第九轮 '+result['offline_engineering_acceptance'])
        with patch('src.round9.validate.report',report):rc=seal(out,summary,command)
        return rc

    def test_final_manifest_covers_final_status_and_report(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);self.assertEqual(self.prepare(out),0)
            self.assertEqual(verify_delivery(out)['status'],'PASS')
            for row in read(out/'artifact_manifest.json')['files']:self.assertEqual(file_record(row['path'])['sha256'],row['sha256'])

    def test_post_seal_report_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);self.prepare(out);text(out/'audit_report.md','tampered')
            r=verify_delivery(out);self.assertEqual(r['status'],'FAIL');self.assertTrue(any(x.startswith('ARTIFACT_RAW_BYTES:') for x in r['errors']))

    def test_encoding_failure_changes_status_and_exit(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);(out/'bad.log').write_bytes(b'\xff');self.assertEqual(self.prepare(out),1)
            self.assertEqual(read(out/'final_status.json')['offline_engineering_acceptance'],'FAIL')
            self.assertEqual(read(out/'command_result.json')['exit_code'],1)
