# socks5_udp_outbound_pool_probe

## Execution and checks

SOCKS UDP outbound pooling preserves per-target association and domain replies. Namespace loopback targets/control streams; expected relay sources, payloads/ports and shutdown boundaries. Keeps original control-EOF failure and datagram readiness semantics.

Topology: proxy-listener: TcpUdpListener → socks5-server; socks5-server: Socks5Server → target-connector; target-connector: UdpConnector.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socks5_udp_outbound_pool_probe`.
