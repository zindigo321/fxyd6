"""ROUND17 source, attempt, command and immutable-copy provenance tests."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.round13.common import EvidenceError, fingerprint, read, record, write
from src.round17 import binding, regression


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND17_TEST_ROOT'))
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_authorized_r17_paths_can_be_added(self):
        for name in ['src/round17/checker.py','tests/test_round17_control.py','tools/export_round17.py']:
            self.assertTrue(binding.allowed_new(name))
        for name in ['src/round16/new.py','tests/test_round16_control.py','configs/round16.json',
                     'src/round17/../round16/new.py','tools/unrelated.py']:
            self.assertFalse(binding.allowed_new(name))

    def attempt(self):
        source = self.root/'src/round17/consumer.py'; source.parent.mkdir(parents=True)
        source.write_text('SAVED = True\n', encoding='utf8')
        rows = [dict(record(source), relative_path='src/round17/consumer.py')]
        attempt = self.root/'work/round17/run/attempts/science_1'; out = attempt/'output'; out.mkdir(parents=True)
        write(attempt/'consumer_code.json', rows)
        with zipfile.ZipFile(attempt/'consumer_code.zip', 'w') as snapshot:
            snapshot.write(source, rows[0]['relative_path'])
        result = dict(status='PASS', exit_code=0, attempt_id=attempt.name, job='science', consumer_identity=fingerprint(rows))
        write(out/'job_result.json', result); write(attempt/'supervised_result.json', result)
        command = dict(attempt_id=attempt.name, job='science', code_manifest=rows, output=str(out),
            command=[sys.executable, '-X', 'utf8', '-B', '-m', 'src.round17.worker', '--work',
                str(attempt.parent.parent), '--out', str(out), '--job', 'science'],
            output_artifacts=binding.artifacts(out), python_exit_code=0, supervised_result_exit_code=0, timeout=False)
        write(attempt/'command_result.json', command)
        return attempt, rows

    def test_attempt_rejects_wrong_worker_command_and_unlisted_output(self):
        attempt, rows = self.attempt()
        with patch.object(binding, 'ROOT', self.root):
            self.assertEqual(binding.verify_attempt(attempt, rows)['profile'], 'ROUND17_V1')
            original = read(attempt/'command_result.json')
            changed = dict(original, command=list(original['command']))
            changed['command'][5] = 'src.round16.worker'
            write(attempt/'command_result.json', changed)
            with self.assertRaisesRegex(EvidenceError, 'ATTEMPT_COMMAND_MISMATCH'):
                binding.verify_attempt(attempt, rows)
            write(attempt/'command_result.json', original)
            (attempt/'output/unbound.json').write_text('{}', encoding='utf8')
            with self.assertRaisesRegex(EvidenceError, 'ATTEMPT_OUTPUT_ARTIFACT_MISMATCH'):
                binding.verify_attempt(attempt, rows)

    def test_wrong_attempt_source_manifest_and_changed_source_are_rejected(self):
        attempt, rows = self.attempt()
        with patch.object(binding, 'ROOT', self.root):
            write(attempt/'consumer_code.json', [])
            with self.assertRaisesRegex(EvidenceError, 'ATTEMPT_CONSUMER_VERSION_MISMATCH'):
                binding.verify_attempt(attempt, rows)
            write(attempt/'consumer_code.json', rows)
            Path(rows[0]['path']).write_text('CHANGED = True\n', encoding='utf8')
            with self.assertRaisesRegex(EvidenceError, 'FROZEN_SOURCE_CHANGED'):
                binding.verify_attempt(attempt, rows)

    def test_isolated_historical_copy_digest_cannot_change(self):
        source = self.root/'src/a.py'; source.parent.mkdir(); source.write_text('saved\n', encoding='utf8')
        row = dict(record(source), relative_path='src/a.py')
        copy = self.root/'isolated/src/a.py'; copy.parent.mkdir(parents=True); shutil.copyfile(source, copy)
        self.assertEqual(len(regression.verify_mapping(self.root, self.root/'isolated', [row])),1)
        copy.write_text('changed\n', encoding='utf8')
        with self.assertRaisesRegex(EvidenceError, 'REGRESSION_COPY_VERSION_MISMATCH'):
            regression.verify_mapping(self.root, self.root/'isolated', [row])


if __name__ == '__main__':unittest.main()
