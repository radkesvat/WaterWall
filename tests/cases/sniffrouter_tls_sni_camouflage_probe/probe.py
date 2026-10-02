#!/usr/bin/env python3
"""Shared SniffRouter/TlsServer SNI fixture: matching/unknown/absent SNI and plain HTTP routing to
protected/cover peers, followed by final connection accounting. Local TLS credentials and bounded
messages/diagnostics; joined peer errors surface. Namespace harness owns runtime. CTest:
waterwall.sniffrouter_tls_sni_camouflage_probe."""
import sys
import os
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.fixtures.sniff_router import main


if __name__ == "__main__":
    main()
