# Socks5 udp requires dynamic provider


Exercises the socks5 udp requires dynamic provider scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tcp-listener`: `TcpListener` → `socks5-server`
- `socks5-server`: `Socks5Server` → `target-connector`
- `target-connector`: `UdpConnector` (terminal or independently bound endpoint)

CTest selections and overrides:

- `waterwall.socks5_udp_requires_dynamic_provider` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `Socks5Server: could not resolve dynamic UDP provider`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.socks5_udp_requires_dynamic_provider$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Expected startup failure: `Socks5Server(udp=true)` behind a TCP-only `TcpListener` is rejected because the finalized
  preceding path has no dynamic `UdpListener`/`TcpUdpListener` provider.
