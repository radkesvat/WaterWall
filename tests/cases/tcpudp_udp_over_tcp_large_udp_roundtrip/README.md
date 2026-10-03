# Tcpudp udp over tcp large udp roundtrip


Exercises the tcpudp udp over tcp large udp roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `outer-udp-connector`
- `outer-udp-connector`: `UdpConnector` (terminal or independently bound endpoint)
- `tcpudp-listener`: `TcpUdpListener` → `uot-client`
- `uot-client`: `UdpOverTcpClient` → `carrier-tcp-connector`
- `carrier-tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `carrier-tcp-listener`: `TcpListener` → `uot-server`
- `uot-server`: `UdpOverTcpServer` → `tcpudp-connector`
- `tcpudp-connector`: `TcpUdpConnector` (terminal or independently bound endpoint)
- `outer-udp-listener`: `UdpListener` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

CTest selections and overrides:

- `waterwall.tcpudp_udp_over_tcp_large_udp_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.tcpudp_udp_over_tcp_large_udp_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies that the same UDP-origin sandwich preserves iperf-sized UDP datagrams larger than the 1500-byte small-buffer
  path.

The request producer spaces its split sends by 5 ms so loopback carrier setup can
progress between sends. UdpListener intentionally drops new datagrams while the
connecting TcpConnector has propagated Pause; sending another request in that
window would test that drop policy instead of frame integrity. All nine chunks,
the 22,000-byte payload limit and the byte/order checks remain unchanged.
