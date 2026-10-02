"""Shared Reality TLS12 GCM/CBC/ChaCha and TLS13 wire/epoch, replay, ordering and close fixture.
Profile remains selected from case CWD; fixed relay/protected sinks and record/payload/accounting
checks. Harness owns runtime; EOF None semantics and scenario order are unchanged. CTest:
waterwall.reality_v2_tls13_wire_camouflage."""
import sys
import os
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.fixtures.reality_wire import main


if __name__ == "__main__":
    main()
