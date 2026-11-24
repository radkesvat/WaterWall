# WireGuard packet roundtrip

Exercises real handshakes and bidirectional inner packets over loopback:
`TesterClient -> WireGuardClient -> UdpConnector`,
`UdpListener -> WireGuardServer(mode=packet) -> TesterServer`.
The server binds to `0.0.0.0` and the client addresses it at `127.0.0.2`. The
handshake and data replies must come from that address to reach the client carrier.
The server learns the authenticated client endpoint. The client carrier has no
fabricated source metadata. Run through the registered namespace test harness.
