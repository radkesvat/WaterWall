# Udp connector packet balance mode roundtrip


Exercises the udp connector packet balance mode roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `packets-to-stream`
- `packets-to-stream`: `PacketsToStream` → `udp-connector`
- `udp-connector`: `UdpConnector` (terminal or independently bound endpoint)
- `udp-listener-25950`: `UdpListener` → `stream-to-packets-25950`
- `stream-to-packets-25950`: `StreamToPackets` → `tester-server-25950`
- `tester-server-25950`: `TesterServer` (terminal or independently bound endpoint)
- `udp-listener-25951`: `UdpListener` → `stream-to-packets-25951`
- `stream-to-packets-25951`: `StreamToPackets` → `tester-server-25951`
- `tester-server-25951`: `TesterServer` (terminal or independently bound endpoint)
- `udp-listener-25952`: `UdpListener` → `stream-to-packets-25952`
- `stream-to-packets-25952`: `StreamToPackets` → `tester-server-25952`
- `tester-server-25952`: `TesterServer` (terminal or independently bound endpoint)
- `udp-listener-25953`: `UdpListener` → `stream-to-packets-25953`
- `stream-to-packets-25953`: `StreamToPackets` → `tester-server-25953`
- `tester-server-25953`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `tester-client.packet-mode=true`, `tester-client.packet-ipv4={"source-ip": "10.92.0.1", "dest-ip": "10.92.0.2", "transport": "udp", "ttl": 64}`, `udp-connector.balance-mode="packet"`, `tester-server-25950.packet-mode=true`, `tester-server-25950.packet-ipv4={"source-ip": "10.92.0.1", "dest-ip": "10.92.0.2", "transport": "udp", "ttl": 64}`, `tester-server-25951.packet-mode=true`, `tester-server-25951.packet-ipv4={"source-ip": "10.92.0.1", "dest-ip": "10.92.0.2", "transport": "udp", "ttl": 64}`, `tester-server-25952.packet-mode=true`, `tester-server-25952.packet-ipv4={"source-ip": "10.92.0.1", "dest-ip": "10.92.0.2", "transport": "udp", "ttl": 64}`, `tester-server-25953.packet-mode=true`, `tester-server-25953.packet-ipv4={"source-ip": "10.92.0.1", "dest-ip": "10.92.0.2", "transport": "udp", "ttl": 64}`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.udp_connector_packet_balance_mode_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.udp_connector_packet_balance_mode_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies that `UdpConnector` accepts `balance-mode: "packet"` with multiple weighted `localhost` domain targets,
  resolves those targets through the local domain-resolution path, and preserves packet integrity while balancing packets across several UDP loopback
  listener ports.
