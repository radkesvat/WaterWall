# Packet analysis all protocols


Exercises the packet analysis all protocols scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `sender`: `PacketSender` → `receiver`
- `receiver`: `PacketReceiver` (terminal or independently bound endpoint)

Scenario choices: `sender.duration-ms=100`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.packet_analysis_all_protocols` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The packet-analysis runner checks its configured protocol/loss report and original exit status; no payload or packet-count requirement is relaxed.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.packet_analysis_all_protocols$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
