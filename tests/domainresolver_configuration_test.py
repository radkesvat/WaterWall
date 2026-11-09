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
from domainresolver_transport_integration import config, connector, node, UUID


def run(binary, label, nodes, valid=False, dns_options=None, diagnostic_name="DomainResolver"):
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
            diagnostic = diagnostic_name in output or (label == "conflicting-predecessor" and "Node Map Failure" in output)
            assert diagnostic, f"{label}: missing resolver/topology diagnostic\n{output}"
            assert "Segmentation fault" not in output and "Assertion" not in output, output


CONSUMERS = ("TcpConnector", "UdpConnector", "TcpUdpConnector", "Router", "Socks5Client",
             "TrojanClient", "VlessClient", "VmessClient", "HttpProxyClient",
             "ConnectionToPackets", "UdpStatelessSocket")
SHARED = {"Router", "Socks5Client", "TrojanClient", "VlessClient", "VmessClient"}


def consumer_config(kind, policy="omitted", extra=None):
    settings = {"address": "dest_context->address", "port": "dest_context->port"}
    if kind in {"VlessClient", "VmessClient"}:
        settings.update(uuid=UUID, protocol="dest_context->protocol")
    elif kind == "TrojanClient":
        settings.update(password="dns-test-password", protocol="dest_context->protocol")
    elif kind == "Socks5Client":
        settings["protocol"] = "dest_context->protocol"
    elif kind == "Router":
        settings = {"rules": [{"resolver-dns": True, "target": "app-out"}]}
    elif kind == "HttpProxyClient":
        settings = {"target-address": "dest_context->address", "port": "dest_context->port"}
    elif kind == "ConnectionToPackets":
        settings = {"source-ipv4": "10.27.0.2"}
    elif kind == "UdpStatelessSocket":
        settings = {"listen-address": "127.0.0.1", "listen-port": 26751}
    if policy != "omitted":
        settings["dns-behaviour"] = policy
    settings.update(extra or {})
    if kind == "UdpStatelessSocket":
        nodes = [node("consumer", kind, settings, "app-out")]
    else:
        nodes = [node("in", "TcpListener", {"address": "127.0.0.1", "port": 26750}, "consumer"),
                 node("consumer", kind, settings)]
        if kind not in {"TcpConnector", "UdpConnector", "TcpUdpConnector"}:
            nodes[-1]["next"] = "app-out"
    if kind in {"ConnectionToPackets", "UdpStatelessSocket"}:
        nodes.append(node("app-out", "BlackHole", {"mode": "passive"}))
    elif kind not in {"TcpConnector", "UdpConnector", "TcpUdpConnector"}:
        nodes.append(connector("app-out"))
    if isinstance(policy, dict) and policy.get("dns-next") == "dns-out":
        nodes.append(connector("dns-out"))
    return nodes


def embedded_configuration(binary, consumers):
    invalid = [None, False, [], {}, {"mode": "native"}, {"resolve": None}, {"resolve": 1},
               {"resolve": True, "unknown": 1}, {"resolve": True, "mode": "Native"},
               {"resolve": True, "strategy": 4}, {"resolve": True, "strategy": "PREFER-IPV4"},
               {"resolve": False, "mode": "native"}, {"resolve": False, "strategy": "only-ipv4"},
               {"resolve": False, "servers": []}, {"resolve": False, "dns-next": "dns-out"},
               {"resolve": True, "servers": ["127.0.0.1"]},
               {"resolve": True, "mode": "direct", "servers": ["localhost"]},
               {"resolve": True, "mode": "chain", "servers": ["127.0.0.1"], "dns-next": "missing"}]
    for kind in consumers:
        for label, policy in (("omitted", "omitted"), ("disabled", {"resolve": False}),
                              ("native", {"resolve": True}),
                              ("direct", {"resolve": True, "mode": "direct", "servers": ["127.0.0.1:53"]}),
                              ("branch", {"resolve": True, "mode": "chain", "servers": ["127.0.0.1:53"],
                                          "dns-next": "dns-out"})):
            run(binary, kind + "-" + label, consumer_config(kind, policy), True)
        for index, policy in enumerate(invalid):
            run(binary, f"{kind}-invalid-{index}", consumer_config(kind, policy), diagnostic_name=kind)
        legacy = {"resolve-domains": False} if kind == "Router" else {"domain-strategy": "only-ipv4"}
        run(binary, kind + "-legacy-conflict", consumer_config(kind, {"resolve": False}, legacy), diagnostic_name=kind)
        shared = {"resolve": True, "mode": "chain", "servers": ["127.0.0.1:53"]}
        run(binary, kind + "-default-entry", consumer_config(kind, shared), kind in SHARED, diagnostic_name=kind)
        if kind in SHARED:
            shared["dns-next"] = "consumer"
            run(binary, kind + "-named-owner", consumer_config(kind, shared), diagnostic_name=kind)
    if "HttpProxyClient" in consumers:
        run(binary, "http-resolution-restriction", consumer_config("HttpProxyClient", {"resolve": True},
                                                                  {"mode": "http", "method": "GET", "body-mode": "none"}),
            diagnostic_name="HttpProxyClient")
    if "ConnectionToPackets" in consumers:
        run(binary, "ctp-family-restriction", consumer_config("ConnectionToPackets", {"resolve": True,
                                                                                    "strategy": "prefer-ipv4"}),
            diagnostic_name="ConnectionToPackets")

    if "VmessClient" in consumers:
        for framing, settings, valid in (
                ("tcp-only", {"security": "zero", "protocol": "tcp"}, False),
                ("udp-only", {"security": "none", "protocol": "udp", "global-padding": True}, False),
                ("both", {"security": "aes-128-gcm", "protocol": "tcp"}, True)):
            for embedded in (False, True):
                if embedded:
                    nodes = consumer_config("VmessClient", {"resolve": True, "mode": "chain",
                        "servers": ["127.0.0.1:53"], "dns-next": "dns-out"})
                else:
                    nodes = config("chain", "127.0.0.1:53")
                # A selected VMess entry has no local DNS policy of its own.
                # Its per-instance framing still must accept UDP and TCP queries.
                nodes[-1] = node("dns-out", "VmessClient", {"uuid": UUID,
                    "target-address": "dest_context->address", "port": "dest_context->port", **settings}, "carrier")
                nodes.append(node("carrier", "TcpConnector", {"address": "127.0.0.1", "port": 26744,
                                                               "fastopen": False}))
                run(binary, f"vmess-entry-{framing}-{'embedded' if embedded else 'standalone'}", nodes, valid)


def main():
    binary = sys.argv[1]
    install_termination_handler()
    for mode in ("omitted", "native", "direct", "direct6", "chain", "chain-default", "shared", "shared-explicit"):
        run(binary, "valid-" + mode, config(mode, "[::1]:53" if mode == "direct6" else "127.0.0.1:53"), True)
    # TcpUdpConnector inserts private resolver preparation before its public inlet.
    # The omitted entry must resolve that callable predecessor during chaining.
    nodes = config("omitted", "127.0.0.1:53")
    nodes[2]["settings"] = {"mode": "chain", "servers": ["127.0.0.1"]}
    nodes[3] = connector("app-out")
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
    embedded_configuration(binary, sys.argv[2:] or CONSUMERS)
    print("DomainResolver constructor, topology rejection and rollback passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
