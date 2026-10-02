# Ping server packets to connection alignment roundtrip


Exercises the ping server packets to connection alignment roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `socks5-client`
- `socks5-client`: `Socks5Client` → `proxy-connector`
- `proxy-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `proxy-listener`: `TcpListener` → `socks5-server`
- `socks5-server`: `Socks5Server` → `connection-to-packets`
- `connection-to-packets`: `ConnectionToPackets` → `ping-client`
- `ping-client`: `PingClient` → `ping-server`
- `ping-server`: `PingServer` → `packets-to-connection`
- `packets-to-connection`: `PacketsToConnection` → `target-connector`
- `target-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `target-listener`: `TcpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `connection-to-packets.mtu=1400`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.ping_server_packets_to_connection_alignment_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.ping_server_packets_to_connection_alignment_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies a TCP roundtrip through PingServer and PacketsToConnection with server reply generation enabled and
  client reply generation omitted, exercising independent endpoint settings and packet alignment.
