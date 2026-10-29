"""One nonrenewable lifecycle and FAIL-dominant status for ROUND17."""
from src.round14.control import Lifecycle, Status, BudgetExceeded
from src.round16.control import classify as archived_classify
import subprocess


def classify(exc):
    if str(exc).startswith('ROUND17_GUARD_'):
        return 'FAIL'
    if isinstance(exc, subprocess.TimeoutExpired):
        return 'BLOCKED'
    return archived_classify(exc)
