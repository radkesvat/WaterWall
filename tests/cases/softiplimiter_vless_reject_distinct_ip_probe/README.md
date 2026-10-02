# Softiplimiter vless reject distinct ip probe


Exercises the softiplimiter vless reject distinct ip probe scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `proxy-listener`: `TcpListener` → `soft-limiter`
- `soft-limiter`: `SoftIpLimiter` → `vless-server`
- `vless-server`: `VlessServer` → `blackhole`
- `blackhole`: `BlackHole` (terminal or independently bound endpoint)

Scenario choices: `blackhole.mode="passive"`. These values define the workload/edge case and are not tuning advice.

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

CTest selections and overrides:

- `waterwall.softiplimiter_vless_reject_distinct_ip_probe` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.softiplimiter_vless_reject_distinct_ip_probe$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
