# Ping direct real adapters roundtrip


Exercises the ping direct real adapters roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `raw-in-out`: `RawSocket` → `carrier-addresses`
- `carrier-addresses`: `IpOverrider` → `ping-server`
- `ping-server`: `PingServer` → `server-tun`
- `server-tun`: `TunDevice` (terminal or independently bound endpoint)

Scenario choices: `server-tun.device-mtu=1491`. These values define the workload/edge case and are not tuning advice.

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

CTest selections and overrides:

- `waterwall.ping_direct_real_adapters_roundtrip` — default runner settings.

Prerequisites: Linux network namespaces, root/CAP_NET_ADMIN and the devices/tools required by the probe; missing prerequisites remain visible skips.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.ping_direct_real_adapters_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: On privileged Linux hosts, injects a wrapped ICMP request through the real
  `RawSocket -> IpOverrider -> PingServer -> TunDevice` server topology with `send-replies: true`, verifies the immediate exact
  Echo Reply, then verifies the kernel-generated response returns in a separate Echo Request followed by a
  matching acknowledgement.

The carrier reuses the actual IPv4 header and inserts Echo framing plus a final
saved-protocol byte, for nine bytes of overhead. A complete 1491-byte native
packet produces a 1500-byte carrier; 1492 bytes is refused. Both codec entry
points reject fragments, so real adapters explicitly reassemble before these
nodes. Address rewriting/restoration belongs to the chain; direct codec pairs
preserve their native tuple. These are fixture expectations, not MTU discovery.

The real-adapter probe checks the 1491/1492-byte native boundary, generated
reply TTL 64/copied TOS, exact Echo body plus trailer, duplicate suppression and
independent data requests. IpOverrider restores the point-to-point TUN addresses
on receive and rewrites loopback carrier addresses on send. RawSocket uses
explicit peer grouping because the decoder is no longer directly adjacent.
