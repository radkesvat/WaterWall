#!/usr/bin/env python3
"""Explicit resolver settings/topology validation in a private namespace.

Checks actual startup and rollback; successful construction is not DNS transport
evidence (the companion transport integration tests exercise that behavior).
"""
import json
import os
from pathlib import Path
import signal
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config, STARTED_MARKER
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from domainresolver_transport_integration import config, node


def run(binary, label, nodes, valid=False, dns_options=None):
    with RunDirectory("ww-resolver-config-") as root:
        core = core_config()
        if dns_options:
            core["dns"] = dns_options
        (root / "core.json").write_text(json.dumps(core))
        (root / "config.json").write_text(json.dumps({"name": label, "nodes": nodes}))
        with Process([binary], cwd=root, log_path=root / "stdout.log",
                     cleanup_signal=signal.SIGTERM) as process:
            deadline = time.monotonic() + 8
            while process.poll() is None and time.monotonic() < deadline:
                output = process.log_path.read_text(errors="replace")
                if valid and STARTED_MARKER in output:
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=8) == 128 + signal.SIGTERM, f"{label}: shutdown failed"
                    return
                time.sleep(.01)
            output = process.log_path.read_text(errors="replace")
            assert not valid, f"{label}: construction failed\n{output}"
            assert process.poll() is not None, f"{label}: invalid config reached runtime\n{output}"
            assert process.returncode != 0, f"{label}: invalid configuration exited successfully"
            diagnostic = "DomainResolver" in output or (label == "conflicting-predecessor" and "Node Map Failure" in output)
            assert diagnostic, f"{label}: missing resolver/topology diagnostic\n{output}"
            assert "Segmentation fault" not in output and "Assertion" not in output, output


def main():
    binary = sys.argv[1]
    install_termination_handler()
    for mode in ("omitted", "native", "direct", "direct6", "chain", "chain-default", "shared", "shared-explicit"):
        run(binary, "valid-" + mode, config(mode, "[::1]:53" if mode == "direct6" else "127.0.0.1:53"), True)
    # TcpConnector inserts its own native resolver before the configured node.
    # The omitted entry must resolve that callable predecessor during chaining.
    nodes = config("omitted", "127.0.0.1:53")
    nodes[2]["settings"] = {"mode": "chain", "servers": ["127.0.0.1"]}
    run(binary, "valid-default-connector-entry", nodes, True)
    del nodes[2]["next"]
    nodes.pop()
    run(binary, "chain-no-default-next", nodes)
    cases = [
        ("mode-type", {"mode": 1}),
        ("mode-value", {"mode": "invalid"}),
        ("native-servers", {"mode": "native", "servers": ["127.0.0.1"]}),
        ("native-egress", {"dns-next": "app-out"}),
        ("direct-no-servers", {"mode": "direct"}),
        ("direct-empty-servers", {"mode": "direct", "servers": []}),
        ("direct-server-type", {"mode": "direct", "servers": [1]}),
        ("direct-server-hostname", {"mode": "direct", "servers": ["localhost:53"]}),
        ("direct-server-zero-port", {"mode": "direct", "servers": ["127.0.0.1:0"]}),
        ("direct-server-overflow-port", {"mode": "direct", "servers": ["127.0.0.1:65536"]}),
        ("direct-ignored-egress", {"mode": "direct", "servers": ["127.0.0.1"], "dns-next": "app-out"}),
        ("chain-null-egress", {"mode": "chain", "servers": ["127.0.0.1"], "dns-next": None}),
        ("chain-empty-egress", {"mode": "chain", "servers": ["127.0.0.1"], "dns-next": ""}),
        ("chain-missing-egress", {"mode": "chain", "servers": ["127.0.0.1"], "dns-next": "missing"}),
        ("chain-self", {"mode": "chain", "servers": ["127.0.0.1"], "dns-next": "resolve"}),
        ("chain-ancestor", {"mode": "chain", "servers": ["127.0.0.1"], "dns-next": "socks"}),
    ]
    for label, settings in cases:
        nodes = config("omitted", "127.0.0.1:53")
        nodes[2]["settings"] = settings
        run(binary, label, nodes)
    nodes = config("chain", "127.0.0.1:53")
    nodes += [node("other-in", "TcpListener", {"address": "127.0.0.1", "port": 26750}, "dns-out")]
    run(binary, "conflicting-predecessor", nodes)
    nodes = config("chain", "127.0.0.1:53")
    nodes[-1] = node("dns-out", "DomainResolver", {"mode": "chain", "servers": ["127.0.0.1"],
                                                  "dns-next": "resolve"}, "bad-out")
    nodes += [node("bad-out", "BlackHole", {"mode": "passive"})]
    run(binary, "resolver-cycle", nodes)
    for field, value in (("socket-send-buffer-size", 65536), ("socket-receive-buffer-size", 65536),
                         ("sortlist", "127.0.0.0/8"), ("resolvconf-path", "/etc/resolv.conf")):
        run(binary, "unsupported-" + field, config("direct", "127.0.0.1:53"),
            dns_options={field: value})
    print("DomainResolver constructor, topology rejection and rollback passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
