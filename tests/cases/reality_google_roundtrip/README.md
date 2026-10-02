# Reality google roundtrip


Exercises the reality google roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `reality-client`
- `reality-client`: `RealityClient` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `reality-server`
- `reality-server`: `RealityServer` → `tester-server`
- `google-visitor`: `TcpConnector` (terminal or independently bound endpoint)
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

Scenario choices: `tester-client.allow-early-response=true`, `reality-client.sni="google.com"`, `tester-server.streaming-response=true`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.reality_google_roundtrip` — default runner settings.

Prerequisites: The external lane and the configured external endpoint/credentials; endpoint availability is part of execution, not a loopback guarantee.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.reality_google_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies `TesterClient -> RealityClient -> TcpConnector` and `TcpListener -> RealityServer -> TesterServer` across a
  real TCP loopback hop while the Reality visitor branch handshakes with `google.com:443`.
