"""Verify HTTP authentication fallback close behavior for both TCP linger settings."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fallback_halfclose_probe.probe import run_probe


if __name__ == "__main__":
    run_probe(fallback_cases=(
        ("HTTP proxy", 26637, "default setting"),
        ("HTTP proxy", 26638, "normal-close linger disabled"),
    ))
