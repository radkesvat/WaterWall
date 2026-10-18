"""Namespace probe entry; shared framing assertions live in api_server_probe.py."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api_server_probe import main

main(Path(__file__).parent)
