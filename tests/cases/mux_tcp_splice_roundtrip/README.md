# Mux tcp splice roundtrip


Exercises the mux tcp splice roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `speedtest-client`: `TesterClient` → `client-to-mux-client`
- `client-to-mux-client`: `TcpConnector` (terminal or independently bound endpoint)
- `mux-client-listener`: `TcpListener` → `mux-client`
- `mux-client`: `MuxClient` → `mux-client-to-mux-server`
- `mux-client-to-mux-server`: `TcpConnector` (terminal or independently bound endpoint)
- `mux-server-listener`: `TcpListener` → `mux-server`
- `mux-server`: `MuxServer` → `mux-server-to-speedtest-server`
- `mux-server-to-speedtest-server`: `TcpConnector` (terminal or independently bound endpoint)
- `speedtest-server-listener`: `TcpListener` → `speedtest-server`
- `speedtest-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `speedtest-client.allow-early-response=true`, `mux-client.mode="fixed-connections-count"`, `mux-client.per-worker-connections-count=1`, `mux-client.child-buffer-limit=67108864`, `mux-server.child-buffer-limit=67108864`, `speedtest-server.streaming-response=true`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.mux_tcp_splice_roundtrip` — WATERWALL_TEST_SPLICE=true.
- `waterwall.mux_tcp_no_splice_roundtrip` — WATERWALL_TEST_SPLICE=false.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.mux_tcp_splice_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
