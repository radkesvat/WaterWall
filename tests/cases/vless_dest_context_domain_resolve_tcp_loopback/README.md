# Vless dest context domain resolve tcp loopback


Exercises the vless dest context domain resolve tcp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `vless-client`
- `vless-client`: `VlessClient` → `proxy-connector`
- `proxy-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `proxy-listener`: `TcpListener` → `vless-server`
- `vless-server`: `VlessServer` → `ip-router`
- `ip-router`: `Router` → `reject-connector`
- `target-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `reject-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `target-listener`: `TcpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Additional selection edges: `ip-router` also selects `target-connector` through its configured rules.

CTest selections and overrides:

- `waterwall.vless_dest_context_domain_resolve_tcp_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.vless_dest_context_domain_resolve_tcp_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
