#!/usr/bin/env python3
"""Router dns.mode=chain with two silent loopback DNS servers: every try times out, tries rotate across
both servers, and the original SOCKS5 CONNECT fails cleanly (failure reply or close, no connect to the
target) while WaterWall stays up for the runner's orderly shutdown. Runs inside the namespace harness.
CTest: waterwall.router_dns_chain_silent_rotation_probe."""
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from router_dns_chain_common import DnsStub, EchoServer, socks_connect_domain

SOCKS_PORT = 27620
ECHO_PORT = 27621
STUB_PORTS = (27622, 27623)
TRIES = 4
TIMEOUT_MS = 200
ATTEMPTS = 2

stub = DnsStub(STUB_PORTS, {"example.test": "127.0.0.1"}, silent=True)
echo = EchoServer("127.0.0.1", ECHO_PORT)
try:
    for attempt in range(ATTEMPTS):
        started = time.monotonic()
        code, data = socks_connect_domain(SOCKS_PORT, "example.test", ECHO_PORT, b"never delivered", timeout=15)
        elapsed = time.monotonic() - started
        assert code != 0, f"attempt {attempt}: CONNECT unexpectedly succeeded"
        assert data is None, f"attempt {attempt}: unexpected payload {data!r}"
        # The first failure waits for the per-try timeouts; no attempt may hang.
        if attempt == 0:
            assert elapsed >= (TRIES - 1) * TIMEOUT_MS / 1000.0, f"failed after only {elapsed:.3f}s"
        assert elapsed < 10, f"attempt {attempt}: failure took {elapsed:.3f}s"

    queries = stub.snapshot()
    ports = {q["port"] for q in queries}
    assert ports == set(STUB_PORTS), f"tries did not rotate across both servers: {queries!r}"
    assert all(q["parsed"] and q["parsed"][2] == "example.test" for q in queries), f"unexpected query {queries!r}"
    # Each failed resolution sends at most `tries` attempts (one or two query types per attempt).
    assert len(queries) <= ATTEMPTS * TRIES * 2, f"more queries than the configured tries: {len(queries)}"
    assert echo.snapshot() == [], f"target was connected despite DNS failure: {echo.snapshot()!r}"
finally:
    echo.close()
    stub.close()
print(f"silent DNS servers rotated ({len(queries)} queries on {sorted(ports)}) and CONNECT failed cleanly")
