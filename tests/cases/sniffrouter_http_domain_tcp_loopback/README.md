# Sniffrouter http domain tcp loopback


Exercises the sniffrouter http domain tcp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `http-client`
- `http-client`: `HttpClient` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `sniff-router`
- `sniff-router`: `SniffRouter` → `default-invalid`
- `default-invalid`: `TcpConnector` (terminal or independently bound endpoint)
- `http-server`: `HttpServer` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Additional selection edges: `sniff-router` also selects `http-server` through its configured rules.

Scenario choices: `tester-client.allow-early-response=true`, `tester-server.streaming-response=true`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.sniffrouter_http_domain_tcp_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.sniffrouter_http_domain_tcp_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies that `SniffRouter` parses an HTTP/1.1 Host header, matches a wildcard domain from a multi-domain route, and
  forwards to that route's target while the top-level fallback `next` points at an invalid connector. The route enables
  both HTTP and TLS detection to exercise the combined detection setting while matching HTTP.
