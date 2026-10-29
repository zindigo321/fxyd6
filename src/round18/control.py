"""One effective preparation-inclusive clock for every R18 parent and child."""
import math
import subprocess
import time
from pathlib import Path

from src.round13.common import read, require
from src.round13.control import Status, BudgetExceeded
from src.round16.control import classify as archived_classify


class Lifecycle:
    def __init__(self, path):
        self.path = Path(path)
        self.data = read(path)
        d = self.data
        record = float(d.get('record_epoch', d['start_epoch']))
        offset = float(d.get('preparation_offset_seconds', 0))
        effective = float(d['effective_start_epoch'])
        require(all(math.isfinite(v) for v in [record, offset, effective]) and offset >= 0,
                'ROUND18_INVALID_CLOCK')
        require(abs(record-offset-effective) <= 1e-6, 'ROUND18_PREPARATION_OFFSET_MISMATCH')
        require(d['start_epoch'] == effective and d.get('start_epoch_already_includes_preparation') is True,
                'ROUND18_START_MUST_INCLUDE_PREPARATION')
        require(d['compute_limit_seconds'] == 6600 and d['total_limit_seconds'] == 7200,
                'ROUND18_CLOCK_LIMITS')
        self.effective_start_epoch = effective
        self._start = time.monotonic() - (time.time()-effective)

    def elapsed(self):
        return time.monotonic()-self._start

    def remaining(self, compute=False):
        return self.data['compute_limit_seconds' if compute else 'total_limit_seconds']-self.elapsed()

    def check(self, compute=False):
        if self.remaining(compute) <= 0:
            raise BudgetExceeded('ROUND18_COMPUTE_DEADLINE' if compute else 'ROUND18_TOTAL_DEADLINE')

    def timeout(self):
        self.check(True)
        return max(.001, min(self.remaining(), self.remaining(True)))


def classify(exc):
    if str(exc).startswith('ROUND18_GUARD_'):
        return 'FAIL'
    if isinstance(exc, subprocess.TimeoutExpired):
        return 'BLOCKED'
    return archived_classify(exc)
