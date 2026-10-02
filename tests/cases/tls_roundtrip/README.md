# Tls roundtrip


Exercises the tls roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `tls-client`
- `tls-client`: `TlsClient` → `tls-server`
- `tls-server`: `TlsServer` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `tester-client.allow-early-response=true`, `tls-client.sni="tls.integration.test"`, `tls-server.sni="tls.integration.test"`, `tester-server.streaming-response=true`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.tls_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.tls_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies `TlsClient` and `TlsServer` chained directly with a self-signed test certificate, peer verification disabled
  on the client, SNI checked by the server, and streaming responses enabled so TLS traffic flows in both directions.
