# Ping new ip icmp roundtrip


Exercises the ping new ip icmp roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `ping-client`
- `ping-client`: `PingClient` → `ping-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)
- `ping-server`: `PingServer` → `tester-server`

Scenario choices: `tester-client.packet-mode=true`, `tester-client.packet-ipv4={"source-ip": "10.80.0.1", "dest-ip": "10.80.0.2", "protocol": 253, "ttl": 64}`, `tester-server.packet-mode=true`, `tester-server.packet-ipv4={"source-ip": "10.80.0.1", "dest-ip": "10.80.0.2", "protocol": 253, "ttl": 64}`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.ping_new_ip_icmp_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.ping_new_ip_icmp_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies a direct `TesterClient -> PingClient -> PingServer -> TesterServer` packet chain in both directions,
  including fresh IPv4/ICMP Echo Requests and one-time inner-packet delivery with `send-replies` omitted at both
  endpoints, exercising the default without generated replies.
