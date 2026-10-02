# reality_v2_tls13_transition_matrix

## Execution and checks

Reality TLS13 transition matrix across staged cover/handoff/application records. Indexed loopback peers, deterministic record sequencing and role/connection/event accounting; exact TLS frames and intentional None EOF. Runtime and credentials are owned by the namespace case harness.

Topology: client-entry: TcpListener → reality-client; reality-client: RealityClient → main-relay-connector; main-relay-connector: TcpConnector; reality-listener: TcpListener → reality-server; reality-server: RealityServer → protected-connector; protected-connector: TcpConnector; cover-relay-connector: TcpConnector.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.reality_v2_tls13_transition_matrix`.

Contract exercised: Runs a deterministic local TLS 1.3 endpoint behind separate destination- and public-wire relays. It covers zero, one,
  and two immediate tickets; a ticket released after REQUEST; byte-split and partial-boundary tickets; a ticket coalesced
  with ACK; cover application data and close_notify before ACK; segmented cover and control records; and independently
  corrupted REQUEST, ACK, and CONFIRM. It also substitutes a prior connection's sequence-zero REQUEST into a fresh
  session and requires session binding to reject it. The server runs with the minimum `sniffing-attempts: 1`, while relay
  evidence proves a genuine protected client Finished record precedes REQUEST. Each success requires an exact protected request/response, authenticated event
  ordering (`REQUEST < ACK < CONFIRM < application`), complete-record destination cutoff, and fixture evidence that the
  selected ticket/segmentation/coalescing action actually happened. Expected pre-confirm failures must not open the
  protected chain. The probe prints per-scenario transition timing and the sampled control-body-length histogram. Python's
  `ssl` API cannot initiate TLS 1.3 KeyUpdate, so both KeyUpdate modes remain deterministic real-BoringSSL unit coverage;
  cryptographic replay/reorder and inner control-identity checks likewise remain in the shared/control unit matrix.
