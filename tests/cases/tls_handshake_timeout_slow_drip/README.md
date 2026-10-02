# Tls handshake timeout slow drip


Exercises the tls handshake timeout slow drip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tcp-listener`: `TcpListener` → `tls-server`
- `tls-server`: `TlsServer` → `protected-invalid`
- `protected-invalid`: `TcpConnector` (terminal or independently bound endpoint)
- `fallback-connector`: `TcpConnector` (terminal or independently bound endpoint)

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

CTest selections and overrides:

- `waterwall.tls_handshake_timeout_slow_drip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.tls_handshake_timeout_slow_drip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Uses a raw TCP probe to verify a TLS-looking slow-drip handshake is closed by `TlsServer`'s hard handshake deadline even
  though each byte arrives before the listener active-idle timeout.
