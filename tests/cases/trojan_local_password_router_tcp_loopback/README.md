# Trojan local password router tcp loopback


Exercises the trojan local password router tcp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `trojan-client`
- `trojan-client`: `TrojanClient` → `proxy-connector`
- `proxy-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `proxy-listener`: `TcpListener` → `trojan-server`
- `trojan-server`: `TrojanServer` → `password-router`
- `password-router`: `Router` → `reject-connector`
- `target-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `reject-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `target-listener`: `TcpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Additional selection edges: `password-router` also selects `target-connector` through its configured rules.

CTest selections and overrides:

- `waterwall.trojan_local_password_router_tcp_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.trojan_local_password_router_tcp_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies `TrojanServer` local password allowlist mode accepts `settings.users`, records the matched local username and
  raw password on the line without a users database, and lets `Router` match both before forwarding to the tester TCP
  listener.
