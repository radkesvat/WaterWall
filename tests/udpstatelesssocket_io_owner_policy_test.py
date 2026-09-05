#!/usr/bin/env python3
"""Keep UdpStatelessSocket's WIO pointer on its owning event worker."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TUNNEL = ROOT / "tunnels" / "UdpStatelessSocket"
DIRECT_IO = re.compile(r"\bstate\s*->\s*socket\s*\.\s*io\b")
LIFECYCLE_FILES = {
    "instance/prepair.c",
    "instance/start.c",
    "instance/stop.c",
}


def main() -> int:
    violations: list[str] = []
    helper = TUNNEL / "common" / "helpers.c"
    helper_matches: list[tuple[int, str]] = []

    for path in sorted(TUNNEL.rglob("*.c")):
        relative = path.relative_to(TUNNEL).as_posix()
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not DIRECT_IO.search(line):
                continue
            if relative == "common/helpers.c":
                helper_matches.append((line_number, line.strip()))
            elif relative not in LIFECYCLE_FILES:
                violations.append(
                    f"{relative}:{line_number}: direct socket.io access is outside owner lifecycle code"
                )

    if len(helper_matches) != 1 or helper_matches[0][1] != "return state->socket.io;":
        rendered = ", ".join(f"{line}:{text}" for line, text in helper_matches) or "none"
        violations.append(
            "common/helpers.c: socket.io must be read only by "
            f"udpstatelesssocketGetOwnerIo(); observed {rendered}"
        )

    stop_source = (TUNNEL / "instance" / "stop.c").read_text(encoding="utf-8")
    request_match = re.search(
        r"void udpstatelesssocketTunnelOnQuiesceRequest\b.*?(?=\nvoid |\Z)",
        stop_source,
        re.DOTALL,
    )
    worker_body = stop_source.split("void udpstatelesssocketTunnelOnWorkerQuiesce", 1)[1].split(
        "void udpstatelesssocketTunnelOnWorkerStop", 1
    )[0]
    if request_match is not None and "wioClose" in request_match.group():
        violations.append("instance/stop.c: main-thread quiesce request closes worker-owned WIO")
    for required in ("currentThreadIsEventWorkerWID(wid)", "wid == state->io_wid", "wioClose(state->socket.io)"):
        if required not in worker_body:
            violations.append(f"instance/stop.c: worker quiesce lost owner check/action {required!r}")

    if violations:
        print("UdpStatelessSocket owner-I/O policy failures:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print("UdpStatelessSocket socket.io access is confined to its owner helper and lifecycle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
