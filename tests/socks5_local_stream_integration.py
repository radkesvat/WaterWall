#!/usr/bin/env python3
"""Run the SOCKS local-stream roundtrip with a VLESS or VMess endpoint."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("protocol", choices=("Vless", "Vmess"))
    args = parser.parse_args()

    tests = Path(__file__).resolve().parent
    template = tests / "cases" / "socks5_local_trojan_tcp_loopback" / "config.json"
    config = json.loads(template.read_text(encoding="utf-8"))
    config["name"] = f"socks5-local-{args.protocol.lower()}-tcp-loopback"
    uuid = "5783a3e7-e373-51cd-8642-c83782b807c5"
    for node in config["nodes"]:
        if node["type"] == "TrojanClient":
            node["type"] = args.protocol + "Client"
            del node["settings"]["password"]
            node["settings"]["uuid"] = uuid
        elif node["type"] == "TrojanServer":
            node["type"] = args.protocol + "Server"
            del node["settings"]["users"]
            node["settings"]["uuid"] = uuid
        elif args.protocol == "Vmess" and node["type"] in ("TesterClient", "TesterServer"):
            # Eight chunks plus framing fit within VMess's 64 KiB pre-auth input limit.
            node.setdefault("settings", {})["chunk-count"] = 8

    with tempfile.TemporaryDirectory(prefix="waterwall-socks-local-stream-") as directory:
        case = Path(directory) / "cases" / config["name"]
        case.mkdir(parents=True)
        (case / "config.json").write_text(json.dumps(config), encoding="utf-8")
        return subprocess.run([
            "bash", str(tests / "run_waterwall_case.sh"), str(args.binary), str(case), "30",
        ], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
