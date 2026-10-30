"""Execute the fixed R18-centered R19 conditional offline study."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.round19.run import cli
if __name__ == '__main__':
    raise SystemExit(cli())
