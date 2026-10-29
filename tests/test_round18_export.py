"""R18 immutable transport, observed exits, and historical subset boundaries."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src.round13.common import EvidenceError, read, record, sha, write
from src.round18 import export, regression


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND18_TEST_ROOT'))
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def transport(self, bound_work=False):
        destination = self.root/'delivered/run'
        path = destination/'transport/entry.json'
        write(path, dict(python_exit_code=0))
        row = dict(path='transport/entry.json', bytes=path.stat().st_size, sha256=sha(path))
        manifest = dict(files=[row])
        receipt = {}
        if bound_work:
            work = self.root/'work/round18/run'
            write(work/'transport/entry.json', dict(python_exit_code=0))
            row['source_path'] = 'transport/entry.json'
            manifest['source_work'] = str(work)
            receipt.update(source_work=str(work), destination=str(destination))
        write(destination/'transport_manifest.json', manifest)
        receipt['manifest_sha256'] = sha(destination/'transport_manifest.json')
        write(destination/'transfer_receipt.json', receipt)
        return destination, path

    def test_original_transport_cannot_be_rebound_by_later_manifest(self):
        destination, path = self.transport()
        self.assertEqual(export.verify_transport(destination)['status'], 'PASS')
        write(path, dict(python_exit_code=1))
        with self.assertRaisesRegex(EvidenceError, 'TRANSPORT_ORIGINAL_MEMBER_BYTES'):
            export.verify_transport(destination)

    def test_unlisted_file_and_duplicate_transport_path_are_rejected(self):
        destination, _ = self.transport()
        write(destination/'unlisted.json', {})
        with self.assertRaisesRegex(EvidenceError, 'TRANSPORT_ORIGINAL_EXACT_SET'):
            export.verify_transport(destination)
        (destination/'unlisted.json').unlink()
        manifest = read(destination/'transport_manifest.json')
        manifest['files'].append(dict(manifest['files'][0]))
        write(destination/'transport_manifest.json', manifest)
        write(destination/'transfer_receipt.json', dict(manifest_sha256=sha(destination/'transport_manifest.json')))
        with self.assertRaisesRegex(EvidenceError, 'TRANSPORT_MEMBER_SCOPE'):
            export.verify_transport(destination)

    def test_exported_copy_is_independently_bound_to_original_work_bytes(self):
        destination, _ = self.transport(bound_work=True)
        with patch.object(export, 'ROOT', self.root):
            self.assertEqual(export.verify_transport(destination)['status'], 'PASS')
            write(self.root/'work/round18/run/transport/entry.json', dict(python_exit_code=9))
            with self.assertRaisesRegex(EvidenceError, 'TRANSPORT_SOURCE_WORK_BYTES'):
                export.verify_transport(destination)

    def exit_records(self):
        destination = self.root/'delivered/run'
        work = self.root/'work/round18/run'
        write(destination/'transport_manifest.json', dict(source_work=str(work)))
        completion = destination/'completion'
        completion.mkdir()
        (completion/'stdout.log').write_bytes(b'actual child output\n')
        (completion/'stderr.log').write_bytes(b'')
        command = dict(argv=[export.sys.executable, '-X', 'utf8', '-B', '-m', 'src.round18.export',
            '--work', str(work), '--destination', str(destination)], cwd=str(self.root),
            destination=str(destination), export_process_exit_code=0)
        for stream in ['stdout', 'stderr']:
            row = record(completion/(stream+'.log'))
            command[stream] = {k: row[k] for k in ['bytes', 'sha256']}
        shell = dict(export_process_exit_code=0, observed_after_process_exit=True,
            actual_argv=[export.sys.executable, '-X', 'utf8', '-B', 'tools/export_round18.py',
                '--work', str(work), '--destination', str(destination)], cwd=str(self.root))
        return destination, command, shell

    def test_actual_exit_record_rejects_wrong_launcher_and_changed_child_output(self):
        destination, command, shell = self.exit_records()
        with patch.object(export, 'ROOT', self.root):
            export.verify_exit_records(destination, command, shell)
            shell['actual_argv'][4] = 'tools/export_round17.py'
            with self.assertRaisesRegex(EvidenceError, 'DELIVERY_LAUNCHER_ARGV_BINDING'):
                export.verify_exit_records(destination, command, shell)
            shell['actual_argv'][4] = 'tools/export_round18.py'
            (destination/'completion/stdout.log').write_bytes(b'changed\n')
            with self.assertRaisesRegex(EvidenceError, 'DELIVERY_EXPORT_LOG_BINDING'):
                export.verify_exit_records(destination, command, shell)

    def test_direct_export_child_preserves_real_failure_and_null_shell_code(self):
        class Clock:
            def __init__(self, _): pass
            def check(self, _): pass
            def remaining(self): return 47.5
        work, destination = self.root/'run', self.root/'output/run'
        work.mkdir()
        fake = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 7)
        with patch.object(export, 'Lifecycle', Clock), patch.object(export, 'ROOT', self.root), \
             patch.object(export, 'install_export_guard', return_value=dict(installed=True)), \
             patch('src.round18.supervise.run', side_effect=fake) as supervised:
            data, code = export.launch(work, destination)
        self.assertEqual((code, data['export_process_exit_code']), (7, 7))
        self.assertIsNone(data['export_shell_exit_code'])
        self.assertFalse(data['shell_used'])
        self.assertEqual(supervised.call_args.kwargs['timeout'], 47.5)

    def test_245_source_subset_preserves_exact_historical_boundaries(self):
        manifest = Path('G:/gpt-file/Codex/outputs/bd-fmb/round17/20261029T114650_offline/sealed/frozen/consumer_code.json')
        rows = read(manifest)
        for count in [168, 185, 203, 223, 245]:
            subset = regression.source_subset(rows, count)
            self.assertEqual(len(subset), count)
            self.assertTrue(all(row in rows for row in subset))
        old = {regression.relative(row) for row in regression.source_subset(rows, 223)}
        self.assertNotIn('tools/export_round17.py', old)
        self.assertIn('tools/export_round17.py', {regression.relative(row) for row in rows})


if __name__ == '__main__':
    unittest.main()
