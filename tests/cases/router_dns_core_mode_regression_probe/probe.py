#!/usr/bin/env python3
"""Regression for Router resolve-domains without a `dns` object: resolution stays on the worker c-ares
channel (core mode) even though a protocol "dns" rule exists. CONNECT localhost (answered locally by
c-ares, no network DNS) reaches the echo peer, and the rule's DNS stub never sees a query.
Runs inside the namespace harness. CTest: waterwall.router_dns_core_mode_regression_probe."""
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from router_dns_chain_common import DnsStub, EchoServer, socks_connect_domain

SOCKS_PORT = 27630
ECHO_PORT = 27631
STUB_PORT = 27632
PAYLOAD = b"core c-ares path " * 32

stub = DnsStub([STUB_PORT], {"localhost": "127.0.0.1"})
echo = EchoServer("127.0.0.1", ECHO_PORT)
try:
    code, data = socks_connect_domain(SOCKS_PORT, "localhost", ECHO_PORT, PAYLOAD)
    assert code == 0, f"SOCKS5 CONNECT reply {code!r}, expected success"
    assert data == PAYLOAD, "echoed bytes differ from the sent payload"
    assert echo.snapshot() == ["127.0.0.1"], f"echo peer saw {echo.snapshot()!r}"
    time.sleep(0.2)
    # dns.servers names the stub while mode is "core": a query there means the core path used the chain servers.
    assert stub.snapshot() == [], f"core mode sent queries through the chain: {stub.snapshot()!r}"
finally:
    echo.close()
    stub.close()
print("core-mode resolve-domains resolved localhost without touching the chain DNS stub")
