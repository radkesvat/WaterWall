# Socks5 noauth tcp loopback


Exercises the socks5 noauth tcp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `socks5-client`
- `socks5-client`: `Socks5Client` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `socks5-server`
- `socks5-server`: `Socks5Server` → `target-connector`
- `target-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `target-listener`: `TcpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

CTest selections and overrides:

- `waterwall.socks5_noauth_tcp_loopback` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.socks5_noauth_tcp_loopback$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies `Socks5Client` without credentials against `Socks5Server(no-auth=true)` across a real TCP proxy hop. The
  SOCKS request target is configured as `localhost` and resolved by
  `domain-strategy=resolve-domains-and-use-only-ipv4` before `Socks5Server` reaches the separate tester TCP listener
  through a `TcpConnector` using `dest_context`, so the case covers method `0x00` negotiation, client-side target
  resolution, and CONNECT target forwarding.
  It also proves `Socks5Server(udp=false)` remains valid behind a TCP-only listener and does not require a dynamic UDP
  provider.
