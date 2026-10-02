# reality_v2_tls13_post_handshake

## Execution and checks

Reality TLS13 post-handshake records/cover traffic do not bypass protected handoff policy. Fixed cover/recording peers, cipher epochs and protected sink/event accounting; exact records and intentional None-at-EOF handling. Requires local TLS fixture credentials and namespace isolation.

Topology: client-entry: TcpListener → reality-client; reality-client: RealityClient → reality-connector; reality-connector: TcpConnector; reality-listener: TcpListener → reality-server; reality-server: RealityServer → protected-connector; protected-connector: TcpConnector; cover-connector: TcpConnector.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.reality_v2_tls13_post_handshake`.

Contract exercised: Runs Reality through a controllable Python/OpenSSL TLS 1.3 cover server configured to emit exactly two session tickets.
  A record-aware relay requires both protected post-handshake ticket records after client Finished, while fixture counters
  require one completed cover handshake and one protected-chain request/response. This verifies that an emitted ticket
  flight does not break authenticated handoff; the paired BoringSSL unit test verifies that TlsClient consumes the records.
  A fixture that silently omits the tickets fails the case.
