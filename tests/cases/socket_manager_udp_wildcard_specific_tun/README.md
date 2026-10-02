# socket_manager_udp_wildcard_specific_tun

## Execution and checks

Privileged SocketManager wildcard/specific listener routing (single/range TCP or UDP) against distinct marker backends. Real loopback/TUN destinations; exact selected markers and joined peer-error accounting. Requires Linux root/TUN/network namespaces. Marker wake-up connections/datagrams remain intentional.

Topology: fixture-tun: TunDevice → fixture-sink; fixture-sink: BlackHole; udp-specific-listener: UdpListener → udp-specific-out; udp-specific-out: UdpConnector; udp-wildcard-listener: UdpListener → udp-wildcard-out; udp-wildcard-out: UdpConnector.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socket_manager_udp_wildcard_specific_tun`.
