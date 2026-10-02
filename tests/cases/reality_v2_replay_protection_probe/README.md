# reality_v2_replay_protection_probe

## Execution and checks

Reality protected handoff rejects replay while valid traffic reaches the protected sink. Real loopback recording relay and event synchronization; exact TLS records and sink accounting. EOF returns None intentionally, preserving protocol closure handling.

Topology: client-entry: TcpListener → reality-client; reality-client: RealityClient → relay-connector; relay-connector: TcpConnector; reality-listener: TcpListener → reality-server; reality-server: RealityServer → protected-connector; protected-connector: TcpConnector; cover-connector: TcpConnector; cover-listener: TcpListener → cover-tls-server; cover-tls-server: TlsServer → cover-blackhole; cover-blackhole: BlackHole.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.reality_v2_replay_protection`.
