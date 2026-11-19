# SpeedTestClient through a direct Trojan TCP pair

Runs `SpeedTestClient -> TrojanClient -> TrojanServer -> SpeedTestServer`
with one bidirectional stream and payload verification. The three-second
watchdog requires the speed-test HELLO to progress before the 60-second
Trojan idle header timer. The initial Trojan request carries the speed-test HELLO.

Run `ctest --preset linux --output-on-failure -R '^waterwall\.speed_client_trojan_direct_tcp$'`.
The case uses no sockets and runs as a short functional smoke check.
