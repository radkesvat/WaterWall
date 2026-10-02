# socks5_udp_dynamic_endpoint_isolation_probe

## Execution and checks

Dynamic UDP associations stay isolated by control line, relay source and target identity. Real namespace loopback datagrams/control streams; exact replies, wrong-target/source rejection and bounded waits. No extra UDP readiness association.

Topology: proxy-listener: TcpUdpListener → socks5-server; socks5-server: Socks5Server → target-connector; target-connector: UdpConnector.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socks5_udp_dynamic_endpoint_isolation_probe`.

Contract exercised: Uses the real SOCKS5 wire protocol to open two same-IP UDP associations, verifies distinct dynamic relay ports and
  source-port pinning, then proves cross-association traffic, the old fixed listener port, and a closed association are
  rejected while the remaining association stays usable. It also checks a concrete foreign peer-IP hint is refused.
