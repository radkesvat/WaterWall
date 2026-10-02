# reality_v2_tls12_cbc_wire_probe

## Execution and checks

Shared Reality TLS12 GCM/CBC/ChaCha and TLS13 wire/epoch, replay, ordering and close fixture. Profile remains selected from case CWD; fixed relay/protected sinks and record/payload/accounting checks. Harness owns runtime; EOF None semantics and scenario order are unchanged.

Topology: client-entry: TcpListener → reality-client; reality-client: RealityClient → relay-connector; relay-connector: TcpConnector; reality-listener: TcpListener → reality-server; reality-server: RealityServer → protected-connector; protected-connector: TcpConnector; cover-connector: TcpConnector; cover-listener: TcpListener → cover-tls-server; cover-tls-server: TlsServer → cover-blackhole; cover-blackhole: BlackHole.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.reality_v2_tls12_cbc_wire_camouflage`.
