# Reality server rejects obsolete max frame size


Exercises the reality server rejects obsolete max frame size scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `reality-server`
- `reality-server`: `RealityServer` → `black-hole`
- `black-hole`: `BlackHole` (terminal or independently bound endpoint)
- `visitor-black-hole`: `BlackHole` (terminal or independently bound endpoint)

Scenario choices: `black-hole.mode="passive"`, `visitor-black-hole.mode="passive"`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.reality_server_rejects_obsolete_max_frame_size` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `RealityServer: 'max-frame-size' is obsolete`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.reality_server_rejects_obsolete_max_frame_size$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Negative startup cases proving Reality v2 rejects the obsolete `max-frame-size` key instead of silently ignoring it.
