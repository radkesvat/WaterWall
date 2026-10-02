# Node layer tundevice tcpconnector conflict


Exercises the node layer tundevice tcpconnector conflict scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tun-in`: `TunDevice` → `tcp-out`
- `tcp-out`: `TcpConnector` (terminal or independently bound endpoint)

Scenario choices: `tun-in.device-mtu=1400`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.node_layer_tundevice_tcpconnector_conflict` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `requires same layer on both sides, but sides resolved to incompatible domains`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.node_layer_tundevice_tcpconnector_conflict$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
