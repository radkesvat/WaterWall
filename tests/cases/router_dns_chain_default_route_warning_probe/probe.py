#!/usr/bin/env python3
"""Router dns.mode=chain without any protocol "dns" rule: startup warns that resolver lines follow the
default route, and the injected UDP query really takes `next` (a TcpUdpConnector using the line's
destination) to the loopback DNS stub. The original CONNECT then reaches the answer and echoes bytes.
Runs inside the namespace harness. CTest: waterwall.router_dns_chain_default_route_warning_probe."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from router_dns_chain_common import QTYPE_A, DnsStub, EchoServer, socks_connect_domain, wait_for_log

SOCKS_PORT = 27610
ECHO_PORT = 27611
STUB_PORT = 27612
PAYLOAD = b"dns via the default route " * 16
# The startup route check: query lines to the configured server match no rule and take the default route.
WARNING = r'(?i)router[^\n]*dns\.servers\[0\][^\n]*match no rule[^\n]*default'

stub = DnsStub([STUB_PORT], {"example.test": "127.0.0.1"})
echo = EchoServer("127.0.0.1", ECHO_PORT)
try:
    code, data = socks_connect_domain(SOCKS_PORT, "example.test", ECHO_PORT, PAYLOAD)
    assert code == 0, f"SOCKS5 CONNECT reply {code!r}, expected success"
    assert data == PAYLOAD, "echoed bytes differ from the sent payload"
    queries = stub.snapshot()
    assert any(q["parsed"] and q["parsed"][2] == "example.test" and q["parsed"][3] == QTYPE_A for q in queries), \
        f"stub saw no A query for example.test: {queries!r}"
    assert echo.snapshot() == ["127.0.0.1"], f"echo peer saw {echo.snapshot()!r}"
    assert wait_for_log(WARNING, timeout=5), 'missing startup warning about no protocol "dns" rule'
finally:
    echo.close()
    stub.close()
print('default route carried chain DNS and the missing protocol "dns" rule was warned about')
