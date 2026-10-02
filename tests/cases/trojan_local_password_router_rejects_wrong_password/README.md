# Trojan local password router rejects wrong password


Exercises the trojan local password router rejects wrong password scenario with the topology in this directory.

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

- `waterwall.trojan_local_password_router_rejects_wrong_password` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `received finish before full response verification`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.trojan_local_password_router_rejects_wrong_password$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Negative case: verifies `Router` does not take a Trojan local-user route when the authenticated username matches but
  the configured password condition is wrong.
