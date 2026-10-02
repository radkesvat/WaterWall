# Socks5 noauth udp encryption loopback


Exercises the socks5 noauth udp encryption loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `socks5-client`
- `socks5-client`: `Socks5Client` → `encryption-client`
- `encryption-client`: `EncryptionClient` → `proxy-connector`
- `proxy-connector`: `TcpUdpConnector` (terminal or independently bound endpoint)
- `proxy-listener`: `TcpUdpListener` → `encryption-server`
- `encryption-server`: `EncryptionServer` → `socks5-server`
- `socks5-server`: `Socks5Server` → `target-connector`
- `target-connector`: `UdpConnector` (terminal or independently bound endpoint)
- `target-listener`: `UdpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

CTest selections and overrides:

- `waterwall.socks5_noauth_udp_encryption_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.socks5_noauth_udp_encryption_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies the same dynamic relay behavior through
  `Socks5Client -> EncryptionClient -> TcpUdpConnector` and
  `TcpUdpListener -> EncryptionServer -> Socks5Server`. This guards that dynamic UDP ingress and replies traverse the
  normal encrypted chain instead of bypassing its middle tunnels.
