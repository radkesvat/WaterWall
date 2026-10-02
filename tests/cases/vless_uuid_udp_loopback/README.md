# Vless uuid udp loopback


Exercises the vless uuid udp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `vless-client`
- `vless-client`: `VlessClient` → `proxy-connector`
- `proxy-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `proxy-listener`: `TcpListener` → `vless-server`
- `vless-server`: `VlessServer` → `target-connector`
- `target-connector`: `UdpConnector` (terminal or independently bound endpoint)
- `target-listener`: `UdpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

CTest selections and overrides:

- `waterwall.vless_uuid_udp_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.vless_uuid_udp_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies `VlessClient(protocol=dest_context->protocol)` sends a plain VLESS v0 UDP request to `VlessServer`, validates
  the response header, wraps datagrams as `uint16_be length + payload`, and reaches a separate UDP tester listener
  through the local UUID allowlist mode.
