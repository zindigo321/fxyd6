import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.round13.common import read, write, sha
from src.round19 import export


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND19_TEST_ROOT'))
        self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)

    def fixture(self):
        folder=self.root/'copy';folder.mkdir();p=folder/'text.txt'
        p.write_text('round19',encoding='utf8')
        manifest=dict(files=[dict(path='text.txt',bytes=p.stat().st_size,sha256=sha(p))])
        write(folder/'transport_manifest.json',manifest)
        write(folder/'transfer_receipt.json',dict(manifest_sha256=sha(folder/'transport_manifest.json')))
        return folder

    def test_legal_transport_and_unlisted_file_rejection(self):
        folder=self.fixture()
        self.assertEqual(export.verify_transport(folder)['status'],'PASS')
        (folder/'unexpected.txt').write_text('extra',encoding='utf8')
        with self.assertRaisesRegex(ValueError,'TRANSPORT_ORIGINAL_EXACT_SET'):export.verify_transport(folder)

    def test_copied_file_tamper_rejected(self):
        folder=self.fixture();(folder/'text.txt').write_text('changed',encoding='utf8')
        with self.assertRaisesRegex(ValueError,'TRANSPORT_ORIGINAL_MEMBER_BYTES'):export.verify_transport(folder)

    def test_same_bytes_wrong_source_work_binding_rejected(self):
        folder=self.fixture()
        source=export.ROOT/'work/round19/fake_source'
        receipt=dict(source_work=str(export.ROOT/'work/round19/different_source'),destination=str(folder))
        with self.assertRaisesRegex(ValueError,'TRANSPORT_RECEIPT_WORK_BINDING'):
            export.verify_work_mapping(folder,dict(source_work=str(source),files=[]),receipt,lambda:None)

    def test_export_roles_are_terminal_and_launcher_exact(self):
        calls=[]
        def capture(work,log,**kwargs):calls.append(kwargs)
        with patch('src.round19.guard.install',capture):
            export.install_export_guard(self.root,self.root/'dest')
            export.install_export_guard(self.root,self.root/'dest',role='finalizer')
            export.install_export_guard(self.root,self.root/'dest',allow_export_child=True)
        self.assertEqual([r['role'] for r in calls],['export_child','finalizer','export_launcher'])
        self.assertEqual(calls[0]['commands'],[]);self.assertEqual(calls[1]['commands'],[])
        command=calls[2]['commands'][0]
        self.assertEqual(command['argv'][-4:],['--work',str(self.root),'--destination',str(self.root/'dest')])
        self.assertEqual(command['cwd'],str(export.ROOT))

    def test_correct_name_in_wrong_export_parent_rejected(self):
        work=export.ROOT/'work/round19/example_run'
        preferred=self.root/'approved'
        self.assertEqual(export.validate_destination(work,preferred/work.name,preferred),preferred/work.name)
        with self.assertRaisesRegex(ValueError,'EXPORT_DESTINATION_BINDING'):
            export.validate_destination(work,self.root/'wrong'/work.name,preferred)


if __name__=='__main__':unittest.main()
