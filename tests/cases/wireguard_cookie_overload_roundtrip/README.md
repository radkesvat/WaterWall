# Wireguard cookie overload roundtrip


Exercises the wireguard cookie overload roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `tester-packet-bridge`
- `wg-client`: `WireGuardDevice` → `wg-packet-bridge`
- `udp-client`: `UdpStatelessSocket` → `wg-client`
- `udp-server`: `UdpStatelessSocket` → `wg-server`
- `wg-server`: `WireGuardDevice` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)
- `tester-packet-bridge`: `Bridge` paired with `wg-packet-bridge`
- `wg-packet-bridge`: `Bridge` paired with `tester-packet-bridge`

Scenario choices: `tester-client.packet-mode=true`, `tester-client.packet-ipv4={"source-ip": "10.45.0.1", "dest-ip": "10.45.0.2", "protocol": 253, "ttl": 64}`, `tester-server.packet-mode=true`, `tester-server.packet-ipv4={"source-ip": "10.45.0.1", "dest-ip": "10.45.0.2", "protocol": 253, "ttl": 64}`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.wireguard_cookie_overload_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The generic roundtrip must pass and the cookie relay must satisfy its final trace verifier. The verifier checks cookie/challenge behavior from the retained relay trace; it owns the enclosing verdict. See [run_wireguard_cookie_case.sh](../../run_wireguard_cookie_case.sh) and [wireguard_cookie_relay.py](../../wireguard_cookie_relay.py).

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.wireguard_cookie_overload_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
