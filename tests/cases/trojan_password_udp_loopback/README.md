# Trojan password udp loopback


Exercises the trojan password udp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `auth-client`: `AuthenticationClient` → `auth-db`
- `auth-db`: `AuthenticationServer` (terminal or independently bound endpoint)
- `tester-client`: `TesterClient` → `trojan-client`
- `trojan-client`: `TrojanClient` → `tls-client`
- `tls-client`: `TlsClient` → `proxy-connector`
- `proxy-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `proxy-listener`: `TcpListener` → `tls-server`
- `tls-server`: `TlsServer` → `trojan-server`
- `trojan-server`: `TrojanServer` → `target-connector`
- `target-connector`: `UdpConnector` (terminal or independently bound endpoint)
- `target-listener`: `UdpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `tls-client.sni="trojan.integration.test"`, `tls-server.sni="trojan.integration.test"`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.trojan_password_udp_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.trojan_password_udp_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies `TrojanClient(protocol=udp)` authenticates with a raw password, sends Trojan `UDP ASSOCIATE` over the TLS/TCP
  carrier, wraps UDP datagrams as Trojan UDP packets, and reaches a separate UDP tester listener.
