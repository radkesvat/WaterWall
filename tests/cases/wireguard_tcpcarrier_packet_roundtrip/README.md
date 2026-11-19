# WireGuard packet roundtrip over TCP

Exercises real WireGuard handshakes and bidirectional inner IPv4/UDP packets
through the client carrier requested by the configuration:

```text
TesterClient(packet) -> WireGuardClient -> UdpOverTcpClient -> TcpConnector
                                                                  |
                                                   loopback TCP :26871
                                                                  |
TcpListener -> UdpOverTcpServer -> UdpConnector
                                       |
                        loopback UDP :26872
                                       |
UdpListener -> WireGuardServer(packet) -> TesterServer(packet)
```

The client chain contains no UdpConnector. UdpOverTcp preserves WireGuard message
boundaries across the TCP byte stream. The WireGuard peer endpoint initializes
the destination context to `127.0.0.1:26870`, where nothing listens. TcpConnector
overrides it with its configured `127.0.0.1:26871`. A successful handshake and
roundtrip therefore require both carrier composition and ordinary destination
overrides to work. The separate server-side UDP bridge preserves
WireGuardServer's existing datagram-ingress contract.

Four processing workers generate and verify distinct inner UDP flows using the
testers' `worker-affine-flow` setting. Their payload checks detect lost, merged,
split, reordered, or corrupted inner packets. The client waits one second before
starting inner traffic so the initial carrier and handshake can become ready.

CTest registrations:

- `waterwall.wireguard_tcpcarrier_packet_roundtrip`: ordinary handshake and traffic.
- `waterwall.wireguard_tcpcarrier_cookie_roundtrip`: the same topology with
  `WATERWALL_TEST_FORCE_SYSTEM_LOAD=1`, requiring cookie-challenged handshakes to
  complete over the TCP carrier before any inner roundtrip can succeed.

Both registrations use the standard private network namespace and case runner;
all sockets bind loopback and no external DNS is required. Success requires all
four tester worker lines to complete before the 30-second deadline. Crashes,
early exit, a missing success marker, and timeout fail the case. The existing
direct-UDP WireGuard case independently retains the single-worker baseline.

The owned normal carrier belongs to WireGuardClient. TcpListener owns the remote
TCP line, and UdpListener owns the server's ingress line; the transforms borrow
those lines. The testers exchange persistent packet lines on the inner sides.
