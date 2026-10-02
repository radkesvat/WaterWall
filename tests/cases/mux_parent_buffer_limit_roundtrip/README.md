# Mux parent buffer limit roundtrip


Exercises the mux parent buffer limit roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `mux-client`
- `mux-client`: `MuxClient` → `mux-server`
- `mux-server`: `MuxServer` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `mux-client.mode="fixed-connections-count"`, `mux-client.per-worker-connections-count=1`, `mux-client.child-buffer-limit=2097152`, `mux-client.parent-buffer-limit=0`, `mux-server.child-buffer-limit=2097152`, `mux-server.parent-buffer-limit=8388608`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.mux_parent_buffer_limit_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.mux_parent_buffer_limit_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
