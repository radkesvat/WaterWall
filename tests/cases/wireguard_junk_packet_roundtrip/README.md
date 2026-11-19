# WireGuard packet roundtrip

Exercises real handshakes and bidirectional inner packets over loopback:
`TesterClient -> WireGuardClient -> UdpConnector`,
`UdpListener -> WireGuardServer(mode=packet) -> TesterServer`.
The server learns the authenticated client endpoint. The client carrier has no
fabricated source metadata. Run through the registered namespace test harness.
