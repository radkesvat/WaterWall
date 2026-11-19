# TesterClient through a direct Trojan UDP pair

Runs `TesterClient -> TrojanClient -> TrojanServer -> TesterServer` with one worker
and two chunks in each direction. TesterClient creates a normal line. TrojanClient
wraps the request in UDP association framing, and TrojanServer initializes
TesterServer when it receives the first datagram.

The case uses no sockets and runs inside the functional lane's network namespace.
The ten-second runner deadline precedes the 60-second idle header timer. Success
requires the tester's response verification marker and a successful runner verdict.
Run `ctest --preset linux --output-on-failure -R '^waterwall\.tester_client_trojan_udp_direct$'`.
