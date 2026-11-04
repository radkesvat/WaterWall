# router_dns_core_mode_regression_probe

## Execution and checks

Regression for the default resolver mode. `Router` has `resolve-domains: true`, a `protocol: "dns"` rule to a
`UdpConnector`, and **no** `dns` object, so its internal `DomainResolver` keeps using the worker c-ares
channel. The SOCKS5 client asks for `CONNECT localhost:27631`; c-ares answers `localhost` locally, so no
network DNS is involved inside the namespace.

Checks: the CONNECT succeeds and echoes its payload; the echo peer accepted one connection on `127.0.0.1`
(the default `prefer-ipv4` core strategy); the DNS stub behind the `protocol: "dns"` rule on `127.0.0.1:27632`
saw no query at all.

Topology: socks-listener: TcpListener → socks-server; socks-server: Socks5Server → router; router: Router →
direct-connector (default), rule `protocol: "dns"` → dns-connector; dns-connector: UdpConnector
(`dest_context->address`/`port`); direct-connector: TcpConnector (`dest_context->address`/`port`).

See [probe.py](probe.py) and the shared [stub/client helpers](../router_dns_chain_common.py). Run through
CTest so namespace prerequisites and private artifacts are preserved.

CTest: `waterwall.router_dns_core_mode_regression_probe`.
