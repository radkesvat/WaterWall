#!/usr/bin/env python3
"""Router dns.mode=chain with a protocol "dns" rule: a SOCKS5 CONNECT to example.test is resolved by an
injected UDP line that the rule sends through UdpConnector to a loopback DNS stub, then the original line
connects to the stub's answer and echoes bytes. Runs inside the namespace harness.
CTest: waterwall.router_dns_chain_rule_udp_probe."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from router_dns_chain_common import QTYPE_A, DnsStub, EchoServer, socks_connect_domain

SOCKS_PORT = 27600
ECHO_PORT = 27601
STUB_PORT = 27602
PAYLOADS = [b"dns-through-the-chain:" + bytes(range(256)) * 4, b"second line, cached answer"]

stub = DnsStub([STUB_PORT], {"example.test": "127.0.0.1"})
echo = EchoServer("127.0.0.1", ECHO_PORT)
try:
    for payload in PAYLOADS:
        code, data = socks_connect_domain(SOCKS_PORT, "example.test", ECHO_PORT, payload)
        assert code == 0, f"SOCKS5 CONNECT reply {code!r}, expected success"
        assert data == payload, "echoed bytes differ from the sent payload"

    queries = stub.snapshot()
    a_queries = [q for q in queries if q["parsed"] and q["parsed"][2] == "example.test" and q["parsed"][3] == QTYPE_A]
    # The second CONNECT must be served from the per-worker cache (answer TTL 60 s, one worker).
    assert len(a_queries) == 1, f"expected exactly one A query for example.test, saw {queries!r}"
    assert all(q["peer"][0] == "127.0.0.1" for q in queries), "query arrived from a non-loopback source"
    assert all(q["parsed"][1] & 0x8100 == 0x0100 for q in a_queries), "query must have QR=0 and RD=1"
    assert all(q["size"] <= 512 for q in queries), "unexpectedly large query"
    accepted = echo.snapshot()
    assert accepted == ["127.0.0.1"] * len(PAYLOADS), f"echo peer saw {accepted!r}"
finally:
    echo.close()
    stub.close()
print(f"chain DNS resolved example.test through the dns rule ({len(a_queries)} A queries)")
