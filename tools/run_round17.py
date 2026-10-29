"""Bounded offline fixed-anchor R17 entry."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.round17.run import cli
if __name__ == '__main__':
    raise SystemExit(cli())
