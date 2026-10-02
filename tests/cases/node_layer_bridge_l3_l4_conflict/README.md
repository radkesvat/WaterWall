# Node layer bridge l3 l4 conflict


Exercises the node layer bridge l3 l4 conflict scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tun-in`: `TunDevice` → `bridge-a`
- `bridge-a`: `Bridge` paired with `bridge-b`
- `tcp-in`: `TcpListener` → `bridge-b`
- `bridge-b`: `Bridge` paired with `bridge-a`

Scenario choices: `tun-in.device-mtu=1400`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.node_layer_bridge_l3_l4_conflict` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `registered layer relation between node`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.node_layer_bridge_l3_l4_conflict$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
