# Ping direct real adapters roundtrip


Exercises the ping direct real adapters roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `raw-in-out`: `RawSocket` → `carrier-addresses`
- `carrier-addresses`: `IpOverrider` → `ping-server`
- `ping-server`: `PingServer` → `server-tun`
- `server-tun`: `TunDevice` (terminal or independently bound endpoint)

The fixture sets `server-tun.device-mtu` to 1,490. IpOverrider translates
incoming wire addresses to the native pair and outgoing carrier addresses back
to the wire pair.

The [probe](probe.py) describes the exchange and its byte/order/exit assertions. It runs against the private copy made by the probe runner.

CTest selections and overrides:

- `waterwall.ping_direct_real_adapters_roundtrip` — default runner settings.

Prerequisites: Linux network namespaces, root/CAP_NET_ADMIN and the devices/tools required by the probe; missing prerequisites remain visible skips.

Success: The probe must finish all of its explicit assertions within the registered deadline and the enclosing runner must accept the runtime exit/markers.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.ping_direct_real_adapters_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

The probe injects a type 253/code 17 carrier through RawSocket, IpOverrider
and PingServer into TunDevice. The kernel's native Echo Reply returns as an
independent type 254/code 66 carrier. The probe checks the carrier addresses,
both visible checksums, the exact native Echo Reply bytes and the final
saved-protocol and sender-role bytes. It also verifies the 1,500-byte carrier
boundary and rejection of a reflected server-role frame. Linux capture can
discard the 1,501-byte datagram before it reaches PingServer. The
[Ping wire unit](../../unittests/tunnels/ping/ping_wire_test.c) checks the
decoder's own size limit directly.
