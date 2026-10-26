"""Fail-dominant status and non-extensible, monotonic process deadlines."""
import time


class DeadlineExceeded(RuntimeError):
    pass


def classify(error):
    if isinstance(error, PermissionError) and str(error).startswith(('ROUND10_', 'ROUND12_GUARD_')):
        return 'FAIL', 'UNAUTHORIZED_ACTION'
    if isinstance(error, DeadlineExceeded):
        return 'BLOCKED', 'DEADLINE_EXCEEDED'
    if isinstance(error, (FileNotFoundError, PermissionError)):
        return 'BLOCKED', 'SOURCE_UNREADABLE'
    return 'FAIL', 'SUBSTANTIVE_ERROR'


class Status:
    def __init__(self):
        self.reasons = []

    def add(self, level, reason):
        if level not in {'PASS', 'BLOCKED', 'FAIL'}:
            raise ValueError('INVALID_STATUS')
        self.reasons.append({'status': level, 'reason': reason})

    @property
    def value(self):
        return max(['PASS'] + [r['status'] for r in self.reasons], key={'PASS': 0, 'BLOCKED': 1, 'FAIL': 2}.get)

    @property
    def exit_code(self):
        return {'PASS': 0, 'BLOCKED': 2, 'FAIL': 1}[self.value]


class Deadline:
    def __init__(self, epoch, wall=time.time, monotonic=time.monotonic):
        self._clock = monotonic
        self._end = monotonic() + max(0, epoch - wall())

    def check(self):
        if self._clock() >= self._end:
            raise DeadlineExceeded('STAGE_DEADLINE_REACHED')

    def invoke(self, fn):
        self.check()
        return fn()
