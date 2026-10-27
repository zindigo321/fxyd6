"""Non-extensible lifecycle and fail-dominant results."""
import time
from .common import read, write


class BudgetExceeded(TimeoutError):
    pass


class Lifecycle:
    def __init__(self, path):
        self.path = path
        self.data = read(path)
        self.total_end = self.data['start_epoch'] + self.data['total_limit_seconds'] - self.data['pre_record_preparation_upper_bound_seconds']
        d=self.data
        phase_end=d['phase_start_epoch']+d['phase_limits'][d['phase']]
        if d['phase']=='input':phase_end-=d['pre_record_preparation_upper_bound_seconds']
        self._monotonic_end=time.monotonic()+min(self.total_end,phase_end)-time.time()

    def remaining(self):
        return self._monotonic_end-time.monotonic()

    def check(self):
        if self.remaining() <= 0:
            raise BudgetExceeded('LIFECYCLE_OR_PHASE_LIMIT_EXCEEDED')

    def phase(self, name):
        self.check()
        d = self.data
        if d['phase'] == name:
            return
        require_order = ['input', 'implementation_replay', 'validation', 'seal_export', 'correction']
        if require_order.index(name) <= require_order.index(d['phase']):
            raise ValueError('PHASE_CANNOT_RESTART')
        now = time.time()
        d.setdefault('completed_phases', []).append(dict(phase=d['phase'], start_epoch=d['phase_start_epoch'], end_epoch=now, elapsed_s=now-d['phase_start_epoch']))
        d.update(phase=name, phase_start_epoch=now)
        write(self.path, d)
        self._monotonic_end=time.monotonic()+min(self.total_end,now+d['phase_limits'][name])-now

    def elapsed(self):
        return time.time() - self.data['start_epoch'] + self.data['pre_record_preparation_upper_bound_seconds']


class Status:
    def __init__(self):
        self.reasons = []

    def add(self, level, reason):
        if level not in {'PASS', 'BLOCKED', 'FAIL'}:
            raise ValueError('UNKNOWN_STATUS')
        self.reasons.append(dict(status=level, reason=reason))

    @property
    def value(self):
        return max(['PASS'] + [r['status'] for r in self.reasons], key={'PASS': 0, 'BLOCKED': 1, 'FAIL': 2}.get)

    @property
    def exit_code(self):
        return {'PASS': 0, 'BLOCKED': 2, 'FAIL': 1}[self.value]


def classify(exc):
    if str(exc).startswith('ROUND13_GUARD_'):
        return 'FAIL'
    if isinstance(exc, (BudgetExceeded, FileNotFoundError, PermissionError)):
        return 'BLOCKED'
    return 'FAIL'
