"""Test configuration: the RAMShift modules live in src/."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
