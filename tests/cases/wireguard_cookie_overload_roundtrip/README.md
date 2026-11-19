# WireGuard packet roundtrip

Exercises real handshakes and bidirectional inner packets over loopback:
`TesterClient -> WireGuardClient -> UdpConnector`,
`UdpListener -> WireGuardServer(mode=packet) -> TesterServer`.
The server learns the authenticated client endpoint. The client carrier has no
fabricated source metadata. Run through the registered namespace test harness.

The recording relay verifies repeated cookies preserve the exact initiation and
response retries. The `wireguard_cookie_source_port_1` and `_4` variants move a
protected initiation to a second UDP source port on the same IP, require its own
cookie challenge, complete that challenge, and verify authenticated roaming back
to the first port with replies delivered through both endpoints.
UDP worker-affine flows and stateless chunk verification preserve each worker's
integrity checks while allowing datagram replies to arrive out of order.
