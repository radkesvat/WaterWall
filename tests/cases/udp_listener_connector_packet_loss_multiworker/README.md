# Udp listener connector packet loss multiworker


Exercises the udp listener connector packet loss multiworker scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `packet-sender`: `PacketSender` → `packets-to-stream`
- `packets-to-stream`: `PacketsToStream` → `udp-connector-a`
- `udp-connector-a`: `UdpConnector` (terminal or independently bound endpoint)
- `udp-listener-a`: `UdpListener` → `udp-connector-b`
- `udp-connector-b`: `UdpConnector` (terminal or independently bound endpoint)
- `udp-listener-b`: `UdpListener` → `stream-to-packets`
- `stream-to-packets`: `StreamToPackets` → `packet-receiver`
- `packet-receiver`: `PacketReceiver` (terminal or independently bound endpoint)

Scenario choices: `packet-sender.duration-ms=200`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.udp_listener_connector_packet_loss_multiworker` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The packet-analysis runner checks its configured protocol/loss report and original exit status; no payload or packet-count requirement is relaxed.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.udp_listener_connector_packet_loss_multiworker$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies a two-hop UDP loopback path across four workers with explicit packet/stream bridges at the outer edges and
  a middle `UdpListener -> UdpConnector` chain, exercising listener-created Layer-4 lines that immediately feed another
  UDP connector, with zero packet loss required.
