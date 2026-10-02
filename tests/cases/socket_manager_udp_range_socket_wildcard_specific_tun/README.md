# socket_manager_udp_range_socket_wildcard_specific_tun

## Execution and checks

Privileged SocketManager wildcard/specific listener routing (single/range TCP or UDP) against distinct marker backends. Real loopback/TUN destinations; exact selected markers and joined peer-error accounting. Requires Linux root/TUN/network namespaces. Marker wake-up connections/datagrams remain intentional.

Topology: fixture-tun: TunDevice → fixture-sink; fixture-sink: BlackHole; udp-range-specific-listener: UdpListener → udp-range-specific-out; udp-range-specific-out: UdpConnector; udp-range-wildcard-listener: UdpListener → udp-range-wildcard-out; udp-range-wildcard-out: UdpConnector.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socket_manager_udp_range_socket_wildcard_specific_tun`.
