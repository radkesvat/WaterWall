# router_dns_chain_rule_udp_probe

## Execution and checks

`Router` with `resolve-domains: true` and `dns.mode: "chain"` resolves a SOCKS5 `CONNECT example.test` by
sending the DNS query over an injected UDP line. The `protocol: "dns"` rule routes that line to
`dns-connector`, which uses the line's destination (the configured server `127.0.0.1:27602`). The probe's
loopback DNS stub answers `example.test -> 127.0.0.1` (A; AAAA gets NOERROR without answers, other names
NXDOMAIN). The original line then reaches the probe's echo peer on `127.0.0.1:27601` through the default
`TcpConnector`.

Checks: both CONNECTs succeed and echo their pipelined payload exactly; the stub saw exactly one A query for
`example.test` from loopback with QR=0 and RD=1 (the second CONNECT is answered from the per-worker cache);
the echo peer accepted two connections on `127.0.0.1`. The payload is sent behind the request because a
`protocol` rule may make Router wait for the first payload.

Topology: socks-listener: TcpListener → socks-server; socks-server: Socks5Server → router; router: Router →
direct-connector (default), rule `protocol: "dns"` → dns-connector; dns-connector: UdpConnector
(`dest_context->address`/`port`); direct-connector: TcpConnector (`dest_context->address`/`port`).

See [probe.py](probe.py) and the shared [stub/client helpers](../router_dns_chain_common.py). Run through
CTest so namespace prerequisites and private artifacts are preserved.

CTest: `waterwall.router_dns_chain_rule_udp_probe`.
