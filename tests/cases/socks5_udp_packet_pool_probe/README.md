# socks5_udp_packet_pool_probe

## Execution and checks

SOCKS UDP packet-side pooling across multiple targets/associations. Fixed real loopback sockets; checks source/target routing and datagram boundaries, with original control-EOF diagnostics and timeout limits.

Topology: proxy-listener: TcpUdpListener → socks5-server; socks5-server: Socks5Server → target-connector; target-connector: UdpConnector.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socks5_udp_packet_pool_probe`.
