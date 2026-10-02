# socks5_udp_pool_stale_reply_probe

## Execution and checks

Delayed replies from retired UDP targets cannot reach replacement associations. Real loopback control/relay sockets, fixed target/association sequence and exact source/payload checks; stale packet rejection and original EOF failures stay explicit.

Topology: proxy-listener: TcpUdpListener → socks5-server; socks5-server: Socks5Server → target-connector; target-connector: UdpConnector.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socks5_udp_pool_stale_reply_probe`.
