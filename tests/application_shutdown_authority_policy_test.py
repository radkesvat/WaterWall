#!/usr/bin/env python3
"""Keep process-shutdown observation inside the orchestration layer."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

removed_symbols = (
    "application_stopping_flag",
    "isApplicationTerminating",
    "signalmanagerIsTerminating",
    "signalmanagerGetShutdownPhase",
    "signalmanagerGetExitCode",
)
for tree_name in ("core", "ww", "tunnels"):
    for path in (ROOT / tree_name).rglob("*.[ch]"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for symbol in removed_symbols:
            if symbol in text:
                raise SystemExit(f"{path.relative_to(ROOT)}: obsolete shutdown authority {symbol}")

for tree_name in ("tunnels", "ww/devices", "ww/net"):
    for path in (ROOT / tree_name).rglob("*.[ch]"):
        if "applicationShutdown" in path.read_text(encoding="utf-8", errors="replace"):
            raise SystemExit(f"{path.relative_to(ROOT)}: component reads the process shutdown controller")

print("process-shutdown state is confined to the orchestration layer")
