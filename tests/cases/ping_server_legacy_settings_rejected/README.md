# Ping server legacy settings rejected


Exercises the ping server legacy settings rejected scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `ping-server`
- `ping-server`: `PingServer` (terminal or independently bound endpoint)

Scenario choices: `tester-client.packet-mode=true`, `tester-client.packet-ipv4={"source-ip": "10.84.0.1", "dest-ip": "10.84.0.2", "protocol": 253, "ttl": 64}`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.ping_server_legacy_settings_rejected` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `PingServer: configuration uses removed Ping wire v1 setting 'strategy'`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.ping_server_legacy_settings_rejected$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verify that both strict Ping parsers reject removed wire-v1 settings with the explicit migration diagnostic.
