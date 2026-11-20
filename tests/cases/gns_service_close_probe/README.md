# GNS service close probe


Closes the service side right after a large response and checks that the client still receives all of it.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `udp-path-listener`: `TcpListener` → `udp-path-client`
- `udp-path-client`: `GnsClient` → `udp-out`
- `udp-out`: `UdpConnector` (UDP to `udp-in`)
- `udp-in`: `UdpListener` → `udp-path-server`
- `udp-path-server`: `GnsServer` → `udp-path-service`
- `udp-path-service`: `TcpConnector` (the probe's service)
- `direct-listener`: `TcpListener` → `direct-client`
- `direct-client`: `GnsClient` → `direct-server`
- `direct-server`: `GnsServer` → `direct-service`
- `direct-service`: `TcpConnector` (the probe's service)

The probe's service reads a short request, writes a 4 MiB response and closes at once. `GnsServer` therefore receives `Finish` while the end of the response is still queued in GNS. Three rounds run on each chain. Both servers set `send-rate` to 8388608 bytes per second, so a response takes about half a second: long enough that its end is queued at the close, and short enough for the probe's deadline. GameNetworkingSockets sends at a fixed rate; at the default of 262144 one response would take sixteen seconds.

CTest selections and overrides:

- `waterwall.gns_service_close_probe` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: every round receives the exact response and then EOF within 10 seconds. A short response, a missing EOF, a timeout or an early runtime exit fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.gns_service_close_probe$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies that `GnsServer` finishes the previous side only after GNS has delivered the data queued before a service-side close.
