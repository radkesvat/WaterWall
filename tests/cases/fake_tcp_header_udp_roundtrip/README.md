# fake_tcp_header_udp_roundtrip

## Purpose

Carries UDP through `FakeTcpHeaderClient` and `FakeTcpHeaderServer` in both
directions inside one process, with an `IpOverrider` rewriting the carrier
addresses between them. It checks that the pair encodes and decodes complete
inner packets end to end, that decode accepts carriers whose checksums
`IpOverrider` updated incrementally, and that receive does not require the
local outgoing header template: the client and server use different sequence,
acknowledgment and TCP options (4 and 8 bytes). Both use the default carrier
ports.

## Topology

```text
TesterClient -> Socks5Client -> TcpUdpConnector ~> TcpUdpListener -> Socks5Server
  -> ConnectionToPackets -> FakeTcpHeaderClient -> IpOverrider -> FakeTcpHeaderServer
  -> PacketsToConnection -> UdpConnector ~> UdpListener -> TesterServer
```

The SOCKS5 UDP entry supplies ordinary UDP associations. `ConnectionToPackets`
turns them into inner packets from `10.90.0.1` to `10.90.0.2:9021`. Each
request crosses client encode, the `IpOverrider` `up` rewrite to
`192.0.2.10 -> 198.51.100.10` and server decode before `UdpConnector` delivers
it to the backend listener; replies take the inverse path through the `down`
rewrite to `198.51.100.10 -> 192.0.2.10`. The carrier path is connected
directly in the chain: there is no raw device and no kernel capture.

## Variants

One variant. It runs with the case runner's default of 4 workers (the case
has no `workers.txt`); each worker's Tester line opens its own UDP association
and exchanges nine payloads of up to 1024 bytes.

## Prerequisites

A build with `FakeTcpHeaderClient`, `FakeTcpHeaderServer` and `IpOverrider`;
CMake registers the case only when all three targets exist. It binds loopback
sockets only (inside the runner's network namespace when integration netns
isolation is enabled) and needs no raw socket, TUN device or firewall rule.

## Verdict

Passes when `TesterClient` logs that all worker lines completed successfully
and Waterwall shuts down with the expected status; a missing marker, crash or
timeout fails it.

CTest: `waterwall.fake_tcp_header_udp_roundtrip`. Kernel capture, carrier
bytes on the wire and the per-flow carrier ports are covered by
`waterwall.fake_tcp_header_raw_roundtrip`,
`waterwall.fake_tcp_header_tun_roundtrip` and
`waterwall.fake_tcp_header_raw_multiqueue_roundtrip` in the privileged lane.
