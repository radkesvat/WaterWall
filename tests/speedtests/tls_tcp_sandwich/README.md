# Tls tcp sandwich


Exercises the tls tcp sandwich scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `speedtest-client`: `SpeedTestClient` → `tls-client`
- `tls-client`: `TlsClient` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `tls-server`
- `tls-server`: `TlsServer` → `speedtest-server`
- `speedtest-server`: `SpeedTestServer` (terminal or independently bound endpoint)

Scenario choices: `speedtest-client.mode="tcp"`, `speedtest-client.direction="bidirectional"`, `speedtest-client.duration-ms=2000`, `speedtest-client.warmup-ms=250`, `speedtest-client.connection-count=1`, `speedtest-client.payload-size=32768`, `speedtest-client.json-summary=true`, `speedtest-client.terminate-on-complete=true`, `tls-client.sni="tls.integration.test"`, `tls-server.sni="tls.integration.test"`, `speedtest-server.json-summary=true`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.speedtest_tls_tcp_sandwich` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The serial speed runner requires its original complete client summary, verified transfers, and original exit/report verdict. Reported throughput is diagnostic for this fixed workload and host; it is not a portable performance threshold.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.speedtest_tls_tcp_sandwich$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
