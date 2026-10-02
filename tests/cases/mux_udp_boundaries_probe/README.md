# Mux udp boundaries probe


Exercises the mux udp boundaries probe scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `udp-ingress`: `UdpListener` → `mux-client`
- `mux-client`: `MuxClient` → `tcp-out`
- `tcp-out`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-in`: `TcpListener` → `mux-server`
- `mux-server`: `MuxServer` → `udp-egress`
- `udp-egress`: `UdpConnector` (terminal or independently bound endpoint)

Scenario choices: `mux-client.mode="fixed-connections-count"`, `mux-client.per-worker-connections-count=1`. These values define the workload/edge case and are not tuning advice.

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

CTest selections and overrides:

- `waterwall.mux_udp_boundaries_probe` — WATERWALL_TEST_SPLICE=true.
- `waterwall.mux_udp_boundaries_no_splice_probe` — WATERWALL_TEST_SPLICE=false.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.mux_udp_boundaries_probe$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
