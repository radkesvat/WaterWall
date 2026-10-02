# Wireguard udpstateless packet roundtrip


Exercises the wireguard udpstateless packet roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `tester-packet-bridge`
- `wg-client`: `WireGuardDevice` → `wg-packet-bridge`
- `udp-client`: `UdpStatelessSocket` → `wg-client`
- `udp-server`: `UdpStatelessSocket` → `wg-server`
- `wg-server`: `WireGuardDevice` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)
- `tester-packet-bridge`: `Bridge` paired with `wg-packet-bridge`
- `wg-packet-bridge`: `Bridge` paired with `tester-packet-bridge`

Scenario choices: `tester-client.packet-mode=true`, `tester-client.packet-ipv4={"source-ip": "10.44.0.1", "dest-ip": "10.44.0.2", "protocol": 253, "ttl": 64}`, `tester-server.packet-mode=true`, `tester-server.packet-ipv4={"source-ip": "10.44.0.1", "dest-ip": "10.44.0.2", "protocol": 253, "ttl": 64}`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.wireguard_udpstateless_packet_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.wireguard_udpstateless_packet_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies two `WireGuardDevice` nodes across real UDP loopback sockets, using packet-mode testers with IPv4 packet
  payloads so AllowedIPs routing and transport encryption are both exercised end to end.
