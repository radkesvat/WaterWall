# Udp listener multiport socket packet loss multiworker


Exercises the udp listener multiport socket packet loss multiworker scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `packet-sender`: `PacketSender` → `packets-to-stream`
- `packets-to-stream`: `PacketsToStream` → `udp-connector`
- `udp-connector`: `UdpConnector` (terminal or independently bound endpoint)
- `udp-listener`: `UdpListener` → `stream-to-packets`
- `stream-to-packets`: `StreamToPackets` → `packet-receiver`
- `packet-receiver`: `PacketReceiver` (terminal or independently bound endpoint)

Scenario choices: `packet-sender.duration-ms=200`. These values define the workload/edge case and are not tuning advice.

CTest selections and overrides:

- `waterwall.udp_listener_multiport_socket_packet_loss_multiworker` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The packet-analysis runner checks its configured protocol/loss report and original exit status; no payload or packet-count requirement is relaxed.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.udp_listener_multiport_socket_packet_loss_multiworker$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

Contract exercised: Verifies `UdpListener` with the socket multiport backend across four workers while a bridged Layer-4 `UdpConnector`
  sends to an integer destination port inside the listener's port range, with zero packet loss required.
