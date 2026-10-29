"""Run the bounded offline round14 study using the existing Python environment."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.round14.run import cli

if __name__=='__main__':raise SystemExit(cli())
