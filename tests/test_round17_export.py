"""The completion layer cannot re-authorize changed original transport bytes."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src.round13.common import EvidenceError, write, sha
from src.round17.export import verify_transport
from src.round17.control import BudgetExceeded, Status
from src.round17 import run


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND17_TEST_ROOT'))
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def transport(self):
        path = self.root/'transport/entry.json'
        write(path, dict(python_exit_code=0))
        write(self.root/'transport_manifest.json', dict(files=[dict(path='transport/entry.json', bytes=path.stat().st_size, sha256=sha(path))]))
        write(self.root/'transfer_receipt.json', dict(manifest_sha256=sha(self.root/'transport_manifest.json')))
        return path

    def test_original_transfer_member_cannot_be_rebound_by_completion(self):
        path = self.transport()
        self.assertEqual(verify_transport(self.root)['status'], 'PASS')
        write(path, dict(python_exit_code=1))
        with self.assertRaisesRegex(EvidenceError, 'TRANSPORT_ORIGINAL_MEMBER_BYTES'):
            verify_transport(self.root)

    def test_unlisted_file_cannot_enter_original_transfer_set(self):
        self.transport()
        write(self.root/'unlisted.json', {})
        with self.assertRaisesRegex(EvidenceError, 'TRANSPORT_ORIGINAL_EXACT_SET'):
            verify_transport(self.root)

    def test_entry_seal_deadline_does_not_downgrade_prior_failure(self):
        state = Status()
        state.add('FAIL', 'independent numeric mismatch')
        with patch.object(run, 'main', side_effect=BudgetExceeded('deadline')), patch.object(run, 'ACTIVE_STATUS', state), \
             patch.object(run, 'ACTIVE_WORK', None), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run.cli(), 1)


if __name__ == '__main__':
    unittest.main()
