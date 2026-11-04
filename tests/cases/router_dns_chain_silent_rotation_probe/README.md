# router_dns_chain_silent_rotation_probe

## Execution and checks

Same topology as [router_dns_chain_rule_udp_probe](../router_dns_chain_rule_udp_probe/README.md), but
`dns.servers` lists two loopback servers (`127.0.0.1:27622`, `127.0.0.1:27623`) with `timeout-ms: 200`,
`tries: 4` and `fallback-to-core: false`, and the probe's DNS stub records queries without ever answering.

Checks, for two consecutive CONNECTs to `example.test`: each fails cleanly (a SOCKS5 failure reply or a close,
never success or payload); the first failure takes at least three per-try timeouts and no attempt takes
10 seconds or more; queries arrived on both server ports (rotation) and never exceeded the configured tries;
the echo peer on `127.0.0.1:27621` was never connected. WaterWall must stay up until the runner's orderly
shutdown and exit with 0 or 143. No project preset runs this case under a sanitizer (the sanitizer test preset runs only `unit`-labelled
tests), so this case does not prove the absence of leaks by itself. To check leaks, build the
`linux-software-crypto-sanitize` preset and run `ctest -L integration -R router_dns` against that `Waterwall`.

Topology: socks-listener: TcpListener → socks-server; socks-server: Socks5Server → router; router: Router →
direct-connector (default), rule `protocol: "dns"` → dns-connector; dns-connector: UdpConnector
(`dest_context->address`/`port`); direct-connector: TcpConnector (`dest_context->address`/`port`).

See [probe.py](probe.py) and the shared [stub/client helpers](../router_dns_chain_common.py). Run through
CTest so namespace prerequisites and private artifacts are preserved.

CTest: `waterwall.router_dns_chain_silent_rotation_probe`.
