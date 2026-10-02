# Bgp4 tcp splice roundtrip


Exercises the bgp4 tcp splice roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `speedtest-client`: `TesterClient` → `client-to-bgp4-client`
- `client-to-bgp4-client`: `TcpConnector` (terminal or independently bound endpoint)
- `bgp4-client-listener`: `TcpListener` → `bgp4-client`
- `bgp4-client`: `Bgp4Client` → `bgp4-client-to-bgp4-server`
- `bgp4-client-to-bgp4-server`: `TcpConnector` (terminal or independently bound endpoint)
- `bgp4-server-listener`: `TcpListener` → `bgp4-server`
- `bgp4-server`: `Bgp4Server` → `bgp4-server-to-speedtest-server`
- `bgp4-server-to-speedtest-server`: `TcpConnector` (terminal or independently bound endpoint)
- `speedtest-server-listener`: `TcpListener` → `speedtest-server`
- `speedtest-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `speedtest-client.allow-early-response=true`, `speedtest-server.streaming-response=true`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.bgp4_tcp_splice_roundtrip` — WATERWALL_TEST_SPLICE=true.
- `waterwall.bgp4_tcp_no_splice_roundtrip` — WATERWALL_TEST_SPLICE=false.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.bgp4_tcp_splice_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
