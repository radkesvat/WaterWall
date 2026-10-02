#!/usr/bin/env python3
"""Shared Reality TLS12 GCM/CBC/ChaCha and TLS13 wire/epoch, replay, ordering and close fixture.
Profile remains selected from case CWD; fixed relay/protected sinks and record/payload/accounting
checks. Harness owns runtime; EOF None semantics and scenario order are unchanged. CTest: direct
CLI/support fixture; called by the registered owning suite."""
import sys
import os
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.fixtures.reality_wire import main


if __name__ == "__main__":
    main()
