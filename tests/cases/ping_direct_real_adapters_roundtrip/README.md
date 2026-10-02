# Ping direct real adapters roundtrip


Exercises the ping direct real adapters roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `raw-in-out`: `RawSocket` → `ping-server`
- `ping-server`: `PingServer` → `server-tun`
- `server-tun`: `TunDevice` (terminal or independently bound endpoint)

Scenario choices: `server-tun.device-mtu=1400`. These values define the workload/edge case and are not tuning advice.

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

CTest selections and overrides:

- `waterwall.ping_direct_real_adapters_roundtrip` — default runner settings.

Prerequisites: Linux network namespaces, root/CAP_NET_ADMIN and the devices/tools required by the probe; missing prerequisites remain visible skips.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.ping_direct_real_adapters_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: On privileged Linux hosts, injects a wrapped ICMP request through the real
  `RawSocket -> PingServer -> TunDevice` server topology with `send-replies: true`, verifies the immediate exact
  Echo Reply, then verifies the kernel-generated response returns in a separate Echo Request followed by a
  matching acknowledgement.
