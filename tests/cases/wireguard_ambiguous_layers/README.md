# Wireguard ambiguous layers


Exercises the wireguard ambiguous layers scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `udp-prev`: `UdpStatelessSocket` → `wireguard`
- `wireguard`: `WireGuardDevice` → `udp-next`
- `udp-next`: `BlackHole` (terminal or independently bound endpoint)

Scenario choices: `udp-next.mode="passive"`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.wireguard_ambiguous_layers` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `chain layers must resolve exactly one L3 packet side and one L4 transport side`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.wireguard_ambiguous_layers$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
