# Sniffrouter non http tcp loopback


Exercises the sniffrouter non http tcp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `sniff-router`
- `sniff-router`: `SniffRouter` → `tester-server`
- `google-com-invalid`: `TcpConnector` (terminal or independently bound endpoint)
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Additional selection edges: `sniff-router` also selects `google-com-invalid` through its configured rules.

CTest selections and overrides:

- `waterwall.sniffrouter_non_http_tcp_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.sniffrouter_non_http_tcp_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies that `SniffRouter` sends non-HTTP first payload bytes to its normal `next` branch across a real TCP loopback
  transport; a configured `google.com` route points at an invalid local connector so accidental route selection fails.
