"""The existing nonrenewable 7200/6600 clock, with round15 status labels."""
from src.round14.control import Lifecycle, Status, BudgetExceeded
from src.round14.control import classify as historical_classify


def classify(exc):
    if str(exc).startswith('ROUND15_GUARD_'):
        return 'FAIL'
    return historical_classify(exc)
