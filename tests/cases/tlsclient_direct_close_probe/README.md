# Tlsclient direct close probe


Exercises the tlsclient direct close probe scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `plain-listener`: `TcpListener` → `tls-client`
- `tls-client`: `TlsClient` → `recording-relay`
- `recording-relay`: `TcpConnector` (terminal or independently bound endpoint)
- `verify-listener`: `TcpListener` → `verify-tls-client`
- `verify-tls-client`: `TlsClient` → `verify-recording-relay`
- `verify-recording-relay`: `TcpConnector` (terminal or independently bound endpoint)

Scenario choices: `tls-client.sni="tls.integration.test"`, `verify-tls-client.sni="tls.integration.test"`. These values define the workload/edge case and are not tuning advice.

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

CTest selections and overrides:

- `waterwall.tlsclient_direct_close_probe` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.tlsclient_direct_close_probe$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Uses a local TLS 1.2 peer behind a recording TCP relay to verify TlsClient direct-close policy: normal protected-side
  close emits no client alert, peer `close_notify` closes without a client response or FIN wait, corrupted records close
  promptly without a client alert, and certificate verification failure does not hang in shutdown.
