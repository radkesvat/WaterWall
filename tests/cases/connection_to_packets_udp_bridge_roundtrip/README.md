# Connection to packets udp bridge roundtrip


Exercises the connection to packets udp bridge roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `socks5-client`
- `socks5-client`: `Socks5Client` → `proxy-connector`
- `proxy-connector`: `TcpUdpConnector` (terminal or independently bound endpoint)
- `proxy-listener`: `TcpUdpListener` → `socks5-server`
- `socks5-server`: `Socks5Server` → `connection-to-packets`
- `connection-to-packets`: `ConnectionToPackets` → `packets-to-connection`
- `packets-to-connection`: `PacketsToConnection` → `target-connector`
- `target-connector`: `UdpConnector` (terminal or independently bound endpoint)
- `target-listener`: `UdpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `connection-to-packets.mtu=1500`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.connection_to_packets_udp_bridge_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.connection_to_packets_udp_bridge_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
