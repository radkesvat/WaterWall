# Obfuscator tls record roundtrip


Exercises the obfuscator tls record roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `obfuscator-client`
- `obfuscator-client`: `ObfuscatorClient` → `obfuscator-client-bridge`
- `obfuscator-client-bridge`: `Bridge` paired with `obfuscator-server-bridge`
- `tester-server`: `TesterServer` → `obfuscator-server`
- `obfuscator-server`: `ObfuscatorServer` → `obfuscator-server-bridge`
- `obfuscator-server-bridge`: `Bridge` paired with `obfuscator-client-bridge`

Scenario choices: `tester-client.packet-mode=true`, `tester-server.packet-mode=true`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.obfuscator_tls_record_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.obfuscator_tls_record_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies the same obfuscation pair while also exercising TLS-like record wrapping and stripping.
