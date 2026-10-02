# Reality v2 tls12 cbc256 roundtrip


Exercises the reality v2 tls12 cbc256 roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `reality-client`
- `reality-client`: `RealityClient` → `reality-connector`
- `reality-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `reality-listener`: `TcpListener` → `reality-server`
- `reality-server`: `RealityServer` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)
- `cover-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `cover-listener`: `TcpListener` → `cover-tls-server`
- `cover-tls-server`: `TlsServer` → `cover-server`
- `cover-server`: `BlackHole` (terminal or independently bound endpoint)

Scenario choices: `tester-client.allow-early-response=true`, `reality-client.sni="tls.integration.test"`, `tester-server.streaming-response=true`, `cover-tls-server.sni="tls.integration.test"`, `cover-server.mode="passive"`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.reality_v2_tls12_cbc256_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.reality_v2_tls12_cbc256_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Forces `ECDHE-RSA-AES256-SHA` and the `aes-gcm` Reality algorithm to cover the AES-256 CBC
  suite family under multi-worker load.
