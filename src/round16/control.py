"""Shared nonrenewable lifecycle, measured from the first preparation."""
from src.round14.control import Lifecycle, Status, BudgetExceeded
from src.round14.control import classify as archived_classify


def classify(exc):
    if str(exc).startswith(('ROUND15_GUARD_', 'ROUND16_GUARD_')):
        return 'FAIL'
    return archived_classify(exc)
