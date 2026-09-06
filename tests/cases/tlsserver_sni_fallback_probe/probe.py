#!/usr/bin/env python3
"""Exercise the same real TLS cover assertions directly through TlsServer."""
import runpy
from pathlib import Path

runpy.run_path(str(Path(__file__).parent.parent / "sniffrouter_tls_sni_camouflage_probe" / "probe.py"), run_name="__main__")
