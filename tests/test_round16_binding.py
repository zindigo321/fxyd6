"""Full R16 source/attempt/output provenance and historical subset isolation."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.round13.common import EvidenceError, fingerprint, read, record, write
from src.round16 import binding, regression, seal


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND16_TEST_ROOT'))
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_historical_203_is_selected_as_168_185_203_without_r16(self):
        rows = [dict(path=str(self.root/f'src/prior/f{i}.py'), relative_path=f'src/prior/f{i}.py') for i in range(168)]
        rows += [dict(path=str(self.root/f'src/round14/f{i}.py'), relative_path=f'src/round14/f{i}.py') for i in range(17)]
        rows += [dict(path=str(self.root/f'src/round15/f{i}.py'), relative_path=f'src/round15/f{i}.py') for i in range(18)]
        for count in [168, 185, 203]:
            selected = regression.source_subset(rows, count, self.root)
            self.assertEqual(selected, rows[:count])
        with self.assertRaisesRegex(EvidenceError, 'REGRESSION_SUBSET203_COUNT'):
            regression.source_subset(rows[:-1], 203, self.root)

    def test_r16_profile_cannot_modify_prior_round_files(self):
        self.assertTrue(binding.allowed_new('src/round16/checker.py'))
        self.assertTrue(binding.allowed_new('tests/test_round16_context.py'))
        for name in ['src/round15/checker.py', 'tests/test_round15_control.py',
                     'configs/round15.json', 'docs/round15.md', 'src/round16/../round15/new.py']:
            self.assertFalse(binding.allowed_new(name))

    def attempt(self):
        source = self.root/'src/round16/consumer.py'; source.parent.mkdir(parents=True)
        source.write_text('SAVED = True\n', encoding='utf8')
        rows = [dict(record(source), relative_path='src/round16/consumer.py')]
        attempt = self.root/'work/round16/run/attempts/science_1'; out = attempt/'output'; out.mkdir(parents=True)
        write(attempt/'consumer_code.json', rows)
        with zipfile.ZipFile(attempt/'consumer_code.zip', 'w') as snapshot:
            snapshot.write(source, rows[0]['relative_path'])
        result = dict(status='PASS', exit_code=0, attempt_id=attempt.name, job='science', consumer_identity=fingerprint(rows))
        write(out/'job_result.json', result); write(attempt/'supervised_result.json', result)
        command = dict(attempt_id=attempt.name, job='science', code_manifest=rows, output=str(out),
            command=[sys.executable, '-X', 'utf8', '-B', '-m', 'src.round16.worker', '--work',
                str(attempt.parent.parent), '--out', str(out), '--job', 'science'],
            output_artifacts=binding.artifacts(out), python_exit_code=0, supervised_result_exit_code=0, timeout=False)
        write(attempt/'command_result.json', command)
        return attempt, rows

    def test_attempt_rejects_source_command_and_output_rebinding(self):
        attempt, rows = self.attempt()
        with patch.object(binding, 'ROOT', self.root):
            self.assertEqual(binding.verify_attempt(attempt, rows)['profile'], 'ROUND16_V1')
            original = read(attempt/'command_result.json')
            changed = dict(original, command=list(original['command']))
            changed['command'][5] = 'src.round15.worker'
            write(attempt/'command_result.json', changed)
            with self.assertRaisesRegex(EvidenceError, 'ATTEMPT_COMMAND_MISMATCH'):
                binding.verify_attempt(attempt, rows)
            write(attempt/'command_result.json', original)
            (attempt/'output/unbound.json').write_text('{}', encoding='utf8')
            with self.assertRaisesRegex(EvidenceError, 'ATTEMPT_OUTPUT_ARTIFACT_MISMATCH'):
                binding.verify_attempt(attempt, rows)
            (attempt/'output/unbound.json').unlink()
            Path(rows[0]['path']).write_text('CHANGED = True\n', encoding='utf8')
            with self.assertRaisesRegex(EvidenceError, 'FROZEN_SOURCE_CHANGED'):
                binding.verify_attempt(attempt, rows)

    def test_isolated_copy_changes_are_rejected(self):
        source = self.root/'src/a.py'; source.parent.mkdir(); source.write_text('saved\n', encoding='utf8')
        row = dict(record(source), relative_path='src/a.py')
        copied = self.root/'isolated/src/a.py'; copied.parent.mkdir(parents=True); shutil.copyfile(source, copied)
        self.assertEqual(len(regression.verify_mapping(self.root, self.root/'isolated', [row])), 1)
        copied.write_text('new\n', encoding='utf8')
        with self.assertRaisesRegex(EvidenceError, 'REGRESSION_COPY_VERSION_MISMATCH'):
            regression.verify_mapping(self.root, self.root/'isolated', [row])

    def test_sealed_prefix_readback_detects_unlisted_and_changed_members(self):
        work = self.root/'work/round16/run'; work.mkdir(parents=True)
        write(work/'starting_scope.json', dict(new_evaluations=0))
        closed = seal.seal_early_prefix(work, 'BLOCKED', 'missing frozen asset')
        folder = Path(closed['delivery'])
        self.assertEqual(read(folder/'final_status.json')['unprocessed'], 60004)
        extra = folder/'extra.json'; extra.write_text('{}', encoding='utf8')
        with self.assertRaisesRegex(EvidenceError, 'SEAL_EXACT_MEMBER_SET'):
            seal.independent_readback(folder)
        extra.unlink(); (folder/'starting_scope.json').write_text('{}', encoding='utf8')
        with self.assertRaisesRegex(EvidenceError, 'SEAL_MEMBER_BYTES'):
            seal.independent_readback(folder)


if __name__ == '__main__':
    unittest.main()
