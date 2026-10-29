"""Bounded offline R16 entry; existing environment only."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.round16.run import cli
if __name__=='__main__':raise SystemExit(cli())
