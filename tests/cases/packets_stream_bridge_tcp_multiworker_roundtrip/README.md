# Packets stream bridge tcp multiworker roundtrip


Exercises the packets stream bridge tcp multiworker roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `packets-to-stream`
- `packets-to-stream`: `PacketsToStream` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `stream-to-packets`
- `stream-to-packets`: `StreamToPackets` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `tester-client.packet-mode=true`, `tester-client.packet-ipv4={"source-ip": "10.92.0.1", "dest-ip": "10.92.0.2", "transport": "tcp", "ttl": 64, "worker-affine-flow": true}`, `tester-server.packet-mode=true`, `tester-server.packet-ipv4={"source-ip": "10.92.0.1", "dest-ip": "10.92.0.2", "transport": "tcp", "ttl": 64, "worker-affine-flow": true}`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.packets_stream_bridge_tcp_multiworker_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.packets_stream_bridge_tcp_multiworker_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
