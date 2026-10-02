# socket_manager_tcp_range_socket_wildcard_specific_tun

## Execution and checks

Privileged SocketManager wildcard/specific listener routing (single/range TCP or UDP) against distinct marker backends. Real loopback/TUN destinations; exact selected markers and joined peer-error accounting. Requires Linux root/TUN/network namespaces. Marker wake-up connections/datagrams remain intentional.

Topology: fixture-tun: TunDevice → fixture-sink; fixture-sink: BlackHole; tcp-range-specific-listener: TcpListener → tcp-range-specific-out; tcp-range-specific-out: TcpConnector; tcp-range-wildcard-listener: TcpListener → tcp-range-wildcard-out; tcp-range-wildcard-out: TcpConnector.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socket_manager_tcp_range_socket_wildcard_specific_tun`.
