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
- `packets-to-connection`: `PacketsToConnection` → `select-transport`
- `select-transport`: `Router` sends TCP to `target-connector` and other traffic to `discard-other-transport`
- `discard-other-transport`: `BlackHole` (passive default)
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

The scenario carries a TCP roundtrip through PingServer and
PacketsToConnection. The two Ping nodes send different ICMP type and code
pairs. The decoder recovers the IPv4 header, the TCP header and its payload
from the reused IPv4 carrier header and the bytes after the ICMP prefix.
