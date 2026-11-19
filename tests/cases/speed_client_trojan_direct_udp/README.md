# SpeedTestClient through a direct Trojan UDP pair

Runs `SpeedTestClient -> TrojanClient -> TrojanServer -> SpeedTestServer`
with one bidirectional stream and payload verification. The three-second
watchdog requires the speed-test HELLO to progress before the 60-second
Trojan idle header timer. The first UDP datagram supplies the destination and opens the backend.

Run `ctest --preset linux --output-on-failure -R '^waterwall\.speed_client_trojan_direct_udp$'`.
The case uses no sockets and runs as a short functional smoke check.
