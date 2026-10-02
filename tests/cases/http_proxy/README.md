# Http proxy


Exercises the http proxy scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `auth-client`: `AuthenticationClient` → `auth-db`
- `auth-db`: `AuthenticationServer` (terminal or independently bound endpoint)
- `http-listener`: `TcpListener` → `http-proxy`
- `http-proxy`: `HttpProxyServer` → `http-out`
- `http-out`: `TcpConnector` (terminal or independently bound endpoint)
- `authenticated-listener`: `TcpListener` → `authenticated-proxy`
- `authenticated-proxy`: `HttpProxyServer` → `authenticated-out`
- `authenticated-out`: `TcpConnector` (terminal or independently bound endpoint)
- `route-listener`: `TcpListener` → `route-proxy`
- `route-proxy`: `HttpProxyServer` → `route-selector`
- `route-selector`: `Router` → `route-failure`
- `route-out`: `TcpConnector` (terminal or independently bound endpoint)
- `route-failure`: `TcpConnector` (terminal or independently bound endpoint)
- `socks-listener`: `TcpListener` → `socks-server`
- `socks-server`: `Socks5Server` → `socks-out`
- `socks-out`: `TcpConnector` (terminal or independently bound endpoint)
- `local-listener`: `TcpListener` → `local-proxy`
- `local-proxy`: `HttpProxyServer` → `local-router`
- `local-router`: `Router` → `local-out`
- `local-route-out`: `TcpConnector` (terminal or independently bound endpoint)
- `local-out`: `TcpConnector` (terminal or independently bound endpoint)
- `fallback-local-listener`: `TcpListener` → `fallback-local`
- `fallback-local`: `HttpProxyServer` → `fallback-local-protected`
- `fallback-local-protected`: `TcpConnector` (terminal or independently bound endpoint)
- `fallback-local-service`: `TcpConnector` (terminal or independently bound endpoint)
- `fallback-tracked-listener`: `TcpListener` → `fallback-tracked`
- `fallback-tracked`: `HttpProxyServer` → `fallback-tracked-protected`
- `fallback-tracked-protected`: `TcpConnector` (terminal or independently bound endpoint)
- `fallback-tracked-service`: `TcpConnector` (terminal or independently bound endpoint)

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

Additional selection edges: `route-selector` also selects `route-out` through its configured rules; `local-router` also selects `local-route-out` through its configured rules.

CTest selections and overrides:

- `waterwall.http_proxy_acceptance` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.http_proxy_acceptance$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
