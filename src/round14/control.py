"""One non-renewable lifecycle; running children share the computation deadline."""
import time
from pathlib import Path
from src.round13.common import read
from src.round13.control import Status, BudgetExceeded


class Lifecycle:
    def __init__(self, path):
        self.path = Path(path)
        self.data = read(path)
        now = time.time()
        self._start = time.monotonic() - (now - self.data['start_epoch'])

    def elapsed(self):
        return time.monotonic() - self._start

    def remaining(self, compute=False):
        limit = self.data['compute_limit_seconds'] if compute else self.data['total_limit_seconds']
        return limit - self.elapsed()

    def check(self, compute=False):
        if self.remaining(compute) <= 0:
            raise BudgetExceeded('ROUND14_COMPUTE_DEADLINE' if compute else 'ROUND14_TOTAL_DEADLINE')

    def timeout(self):
        self.check(True)
        return max(.001, min(self.remaining(), self.remaining(True)))


def classify(exc):
    if str(exc).startswith(('ROUND9_', 'ROUND13_GUARD_', 'ROUND14_GUARD_')):
        return 'FAIL'
    if isinstance(exc, (BudgetExceeded, FileNotFoundError, PermissionError)):
        return 'BLOCKED'
    return 'FAIL'
