import unittest
from src.round12.control import Deadline, DeadlineExceeded, Status, classify


class Controls(unittest.TestCase):
    def test_positive_control(self):
        s = Status(); s.add('PASS', 'VALID'); self.assertEqual((s.value, s.exit_code), ('PASS', 0))

    def test_blocked(self):
        s = Status(); s.add('BLOCKED', 'EXPIRED'); self.assertEqual((s.value, s.exit_code), ('BLOCKED', 2))

    def test_fail_then_timeout(self):
        s = Status(); s.add('FAIL', 'BAD_CERTIFICATE'); s.add('BLOCKED', 'EXPIRED')
        self.assertEqual((s.value, s.exit_code), ('FAIL', 1)); self.assertEqual(len(s.reasons), 2)

    def test_timeout_then_fail(self):
        s = Status(); s.add('BLOCKED', 'EXPIRED'); s.add('FAIL', 'BAD_BYTES'); self.assertEqual(s.exit_code, 1)

    def test_missing_file(self):
        self.assertEqual(classify(FileNotFoundError('source')), ('BLOCKED', 'SOURCE_UNREADABLE'))

    def test_permission(self):
        self.assertEqual(classify(PermissionError('source')), ('BLOCKED', 'SOURCE_UNREADABLE'))

    def test_native_denial(self):
        self.assertEqual(classify(PermissionError('ROUND10_NATIVE_IMPORT')), ('FAIL', 'UNAUTHORIZED_ACTION'))

    def test_write_denial(self):
        self.assertEqual(classify(PermissionError('ROUND12_GUARD_WRITE_OUTSIDE')), ('FAIL', 'UNAUTHORIZED_ACTION'))

    def test_bad_bytes(self):
        self.assertEqual(classify(ValueError('BYTE_MISMATCH')), ('FAIL', 'SUBSTANTIVE_ERROR'))

    def test_deadline_positive(self):
        d = Deadline(12, wall=lambda: 10, monotonic=lambda: 5); self.assertEqual(d.invoke(lambda: 7), 7)

    def test_expired_prevents_action(self):
        calls = []; d = Deadline(10, wall=lambda: 10, monotonic=lambda: 5)
        with self.assertRaisesRegex(DeadlineExceeded, '^STAGE_DEADLINE_REACHED$'):
            d.invoke(lambda: calls.append('experiment'))
        self.assertEqual(calls, [])

    def test_monotonic_clock(self):
        tick = [5]; d = Deadline(12, wall=lambda: 10, monotonic=lambda: tick[0]); tick[0] = 7
        with self.assertRaisesRegex(DeadlineExceeded, '^STAGE_DEADLINE_REACHED$'): d.check()

    def test_no_clock_reset_on_recheck(self):
        tick = [5]; d = Deadline(12, wall=lambda: 10, monotonic=lambda: tick[0]); d.check(); tick[0] = 7
        for _ in range(3):
            with self.assertRaisesRegex(DeadlineExceeded, '^STAGE_DEADLINE_REACHED$'): d.check()

    def test_fail_cannot_be_cleared(self):
        s = Status(); s.add('FAIL', 'BAD'); s.add('PASS', 'OTHER_OK'); self.assertEqual(s.exit_code, 1)
