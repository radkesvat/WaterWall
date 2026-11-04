# fake_tcp_header_udp_roundtrip

Carries UDP through both FakeTcpHeader nodes in one process. Both explicitly
select `payload-protocol: 17`. Fake TCP is inserted after the existing IPv4
header, leaving the native UDP header and application bytes immediately after
it. There is one IPv4 header and no preserved inner address tuple.

```text
TesterClient -> Socks5Client -> TcpUdpConnector ~> TcpUdpListener -> Socks5Server
  -> ConnectionToPackets -> FakeTcpHeaderClient -> client IpOverrider
  -> server IpOverrider -> FakeTcpHeaderServer -> PacketsToConnection
  -> UdpConnector ~> UdpListener -> TesterServer
```

CTP creates native packets from `10.90.0.1` to `10.90.0.2:9021`.
The client override sends `192.0.2.10 -> 198.51.100.10` upstream and restores
`10.90.0.2 -> 10.90.0.1` downstream. The server override restores
`10.90.0.1 -> 10.90.0.2` upstream and sends
`198.51.100.10 -> 192.0.2.10` downstream. Both receive-side rewrites precede
decoding. This exercises checksum normalization and restoration through the
actual IpOverrider callbacks while keeping CTP's original connection tuple.

The peers use different sequence/acknowledgment templates and four fake TCP
option bytes. Each native packet is limited to 1476 bytes, leaving 24 bytes for
the fake TCP header within the 1500-byte final-packet limit. This is a native IP
MTU, not a UDP payload limit. Complete unfragmented native datagrams are required;
reassemble upstream when accepting fragments. The transform adds no handshake,
retransmission, encryption or reliability.

The default runner uses four workers, each exchanging nine verified payloads
of up to 1024 bytes through an ordinary SOCKS5 UDP association. CMake requires
both FakeTcpHeader targets and IpOverrider. Loopback sockets run inside the
namespace harness; this case needs no raw socket, TUN device or firewall rule.

CTest: `waterwall.fake_tcp_header_udp_roundtrip`. Passing requires the normal
TesterClient completion marker and accepted runner shutdown status. Raw-wire
layout, normalized hidden native checksums, exact original application reply
tuples, capture exclusions and firewall cleanup are covered separately by the
privileged `fake_tcp_header_raw`, `fake_tcp_header_raw_multiqueue` and
`fake_tcp_header_tun` roundtrip tests. The TUN case chooses deterministic native
UDP tuples and checks their exact carrier-port distribution; the raw CTP cases
check their actual ephemeral native tuples and stable reverse mapping.
