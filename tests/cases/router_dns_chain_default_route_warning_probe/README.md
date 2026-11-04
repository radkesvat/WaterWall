# router_dns_chain_default_route_warning_probe

## Execution and checks

`Router` uses `dns.mode: "chain"` but has no rule with `protocol: "dns"`. Its only rule
(`destination-port: 9`) matches neither the injected resolver line nor the original line, so the DNS query
follows the default `next`: a `TcpUdpConnector` that uses the line's destination and therefore delivers the
UDP query to the probe's loopback DNS stub on `127.0.0.1:27612`. The original SOCKS5
`CONNECT example.test` then takes the same default connector over TCP to the echo peer on `127.0.0.1:27611`.

Checks: the CONNECT succeeds and echoes its payload; the stub saw an A query for `example.test`; the echo
peer accepted one connection on `127.0.0.1`; and the runtime logs contain Router's startup warning that no
rule uses `protocol "dns"` (matched loosely by regex, not by exact wording).

Topology: socks-listener: TcpListener → socks-server; socks-server: Socks5Server → router; router: Router →
default-connector (default), rule `destination-port: 9` → reject-connector; reject-connector: TcpConnector;
default-connector: TcpUdpConnector (`dest_context->address`/`port`).

See [probe.py](probe.py) and the shared [stub/client helpers](../router_dns_chain_common.py). Run through
CTest so namespace prerequisites and private artifacts are preserved.

CTest: `waterwall.router_dns_chain_default_route_warning_probe`.
