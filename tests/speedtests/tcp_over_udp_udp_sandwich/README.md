# Tcp over udp udp sandwich


Exercises the tcp over udp udp sandwich scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `speedtest-client`: `SpeedTestClient` → `tou-client`
- `tou-client`: `TcpOverUdpClient` → `udp-connector`
- `udp-connector`: `UdpConnector` (terminal or independently bound endpoint)
- `udp-listener`: `UdpListener` → `tou-server`
- `tou-server`: `TcpOverUdpServer` → `speedtest-server`
- `speedtest-server`: `SpeedTestServer` (terminal or independently bound endpoint)

Scenario choices: `speedtest-client.verify-payload=true`, `speedtest-client.mode="tcp"`, `speedtest-client.direction="bidirectional"`, `speedtest-client.duration-ms=2000`, `speedtest-client.warmup-ms=250`, `speedtest-client.connection-count=1`, `speedtest-client.payload-size=32768`, `speedtest-client.json-summary=true`, `speedtest-client.terminate-on-complete=true`, `udp-connector.balance-mode="packet"`, `speedtest-server.json-summary=true`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.speedtest_tcp_over_udp_udp_sandwich` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The serial speed runner requires its original complete client summary, verified transfers, and original exit/report verdict. Reported throughput is diagnostic for this fixed workload and host; it is not a portable performance threshold.

Discover properties with `ctest --test-dir build/linux -C Release -N -V -R '^waterwall\.speedtest_tcp_over_udp_udp_sandwich$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
