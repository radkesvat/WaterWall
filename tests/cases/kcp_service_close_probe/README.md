# KCP service close probe


Closes the service side right after a large response and checks that the client still receives all of it.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `udp-path-listener`: `TcpListener` → `udp-path-client`
- `udp-path-client`: `KcpClient` → `udp-out`
- `udp-out`: `UdpConnector` (UDP to `udp-in`)
- `udp-in`: `UdpListener` → `udp-path-server`
- `udp-path-server`: `KcpServer` → `udp-path-service`
- `udp-path-service`: `TcpConnector` (the probe's service)
- `direct-listener`: `TcpListener` → `direct-client`
- `direct-client`: `KcpClient` → `direct-server`
- `direct-server`: `KcpServer` → `direct-service`
- `direct-service`: `TcpConnector` (the probe's service)

The probe's service reads a short request, writes a 4 MiB response and closes at once, so `KcpServer` receives `Finish` while most of the response is still queued in KCP. Three rounds run on each chain. Both clients use a 128-segment `kcp-recv-window`, the smallest KCP accepts, which paces the transfer so the run does not depend on loopback buffer sizes.

CTest selections and overrides:

- `waterwall.kcp_service_close_probe` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: every round receives the exact response and then EOF within 10 seconds. A short response, a missing EOF, a timeout or an early runtime exit fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.kcp_service_close_probe$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies that `KcpServer` finishes the previous side only after KCP has delivered the data queued before a service-side close.
