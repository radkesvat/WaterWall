# Packet analysis unexpected protocol


Exercises the packet analysis unexpected protocol scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `receiver`: `PacketReceiver` → `receiver-bridge`
- `receiver-bridge`: `Bridge` paired with `sender-bridge`
- `sender`: `TesterClient` → `sender-bridge`
- `sender-bridge`: `Bridge` paired with `receiver-bridge`

Scenario choices: `sender.packet-mode=true`, `sender.packet-ipv4={"source-ip": "198.51.101.10", "dest-ip": "203.0.113.20", "protocol": 253, "ttl": 64}`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.packet_analysis_unexpected_protocol` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The packet-analysis runner checks its configured protocol/loss report and original exit status; no payload or packet-count requirement is relaxed.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.packet_analysis_unexpected_protocol$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
