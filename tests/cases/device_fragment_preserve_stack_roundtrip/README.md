# Device fragment preserve stack roundtrip


Exercises the device fragment preserve stack roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tun`: `TunDevice` → `stack`
- `stack`: `PacketsToConnection` → `out`
- `out`: `UdpConnector` (terminal or independently bound endpoint)

Scenario choices: `tun.device-mtu=1500`. These values define the workload/edge case and are not tuning advice.

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

CTest selections and overrides:

- `waterwall.device_fragment_preserve_stack_roundtrip` — default runner settings.

Prerequisites: Linux network namespaces, root/CAP_NET_ADMIN and the devices/tools required by the probe; missing prerequisites remain visible skips.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.device_fragment_preserve_stack_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
