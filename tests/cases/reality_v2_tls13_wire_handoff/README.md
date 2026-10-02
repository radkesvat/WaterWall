# reality_v2_tls13_wire_handoff

## Execution and checks

Reality TLS13 REQUEST/ACK/CONFIRM handoff preserves wire epochs and protected application bytes. Fixed relay/sink sequence and exact TLS record/event checks; intentional None-at-EOF decoding. Namespace harness owns the runtime.

Topology: client-entry: TcpListener → reality-client; reality-client: RealityClient → relay-connector; relay-connector: TcpConnector; reality-listener: TcpListener → reality-server; reality-server: RealityServer → protected-connector; protected-connector: TcpConnector; cover-connector: TcpConnector; cover-listener: TcpListener → cover-tls-server; cover-tls-server: TlsServer → cover-blackhole; cover-blackhole: BlackHole.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.reality_v2_tls13_wire_handoff`.

Contract exercised: Repeats twelve authenticated handoffs through a keyless, record-aware relay. It checks that REQUEST, ACK, and CONFIRM
  occupy plausible TLS 1.3 application records with reviewed body lengths in `22..1172`, that the 36 sampled controls do
  not collapse to one public length, and that no handoff or application marker is visible. It also requires genuine
  protected cover-handshake records before ACK, REQUEST-before-ACK ordering, CONFIRM-before-application ordering, the
  negotiated TLS 1.3 cipher, and exactly one protected request/response per sample. The probe submits application bytes
  immediately; event ordering on the public stream proves they remain queued until after CONFIRM without classifying the
  randomly padded controls by public length. The post-handshake case likewise exercises RealityClient's pre-ACK queue.
