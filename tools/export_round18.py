"""Supervise the actual export child, then finalize after the outer Shell exits."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.round18.export import outer_cli
if __name__ == '__main__':
    raise SystemExit(outer_cli())
