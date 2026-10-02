# Device fragment policy invalid


Exercises the device fragment policy invalid scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tun`: `TunDevice` → `stack`
- `stack`: `PacketsToConnection` → `out`
- `out`: `UdpConnector` (terminal or independently bound endpoint)

Scenario choices: `tun.device-mtu=1500`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.device_fragment_policy_invalid` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `Device source fragment-policy must be reassemble or preserve-fragments`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.device_fragment_policy_invalid$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
