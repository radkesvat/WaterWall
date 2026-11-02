# Http websocket bidirectional tcp loopback


Exercises the http websocket bidirectional tcp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `http-client`
- `http-client`: `HttpClient` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `http-server`
- `http-server`: `HttpServer` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `tester-client.allow-early-response=true`, `tester-server.streaming-response=true`. These values define the workload/edge case and are not tuning advice.

The client preserves all eleven verification chunks (3,216,936 bytes) but sends
at most 16 KiB per dispatch, yielding for 1 ms between deliveries. This lets the
socket handshake progress while keeping the successful roundtrip within HTTP's
2 MiB byte / 8 MiB charge waiting budget. Sending the entire request before the
peer can respond is an overload case; focused HTTP unit tests verify its refusal.

CTest selections and overrides:

- `waterwall.http_websocket_bidirectional_tcp_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.http_websocket_bidirectional_tcp_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies the same WebSocket transport across a real TCP loopback transport, including clean shutdown after the tester
  success marker.
