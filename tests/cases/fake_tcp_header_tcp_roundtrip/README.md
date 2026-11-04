# fake_tcp_header_tcp_roundtrip

Tests real native TCP connection establishment and bidirectional verified
payload through FakeTcpHeaderClient and FakeTcpHeaderServer. Each encoded
packet records protocol 6 in a byte after fake TCP/options, followed by the
original TCP header and body within one IPv4 packet. No protocol setting is
needed. Neither node negotiates a carrier connection or adds reliability; the
native TCP endpoints provide the handshake and stream.

```text
TesterClient -> TcpConnector ~> TcpListener -> ConnectionToPackets
  -> FakeTcpHeaderClient -> client IpOverrider -> server IpOverrider
  -> FakeTcpHeaderServer -> PacketsToConnection
  -> TcpConnector ~> TcpListener -> TesterServer
```

The CTP tuple is `10.90.0.1 -> 10.90.0.2:9001`. The client override sends
`192.0.2.10 -> 198.51.100.10` upstream and restores
`10.90.0.2 -> 10.90.0.1` downstream; the server override restores
`10.90.0.1 -> 10.90.0.2` upstream and sends the reverse public tuple downstream.
Receive-side rewrites precede decode. Hidden native checksums normalize address
contributions to zero during encoding and restore the current native addresses
after decode, so both CTP routing and reply delivery retain their original tuple.

The peers use no fake TCP options, and CTP's 1479-byte native IP MTU leaves
21 bytes (20 for fake TCP and one for the protocol byte) below the 1500-byte
final-packet limit. Complete unfragmented IPv4 packets are required; upstream
device reassembly handles fragmented input.
This case uses the small existing CTP TCP bridge workload with one worker.

CTest: `waterwall.fake_tcp_header_tcp_roundtrip`. Both FakeTcpHeader nodes,
IpOverrider, CTP, PTC and the TCP adapters must be enabled. Loopback sockets run
inside the network namespace harness. Passing requires the normal TesterClient
completion marker and runner exit status; missing connection establishment,
incorrect bytes, early exit or timeout fail. The privileged
`waterwall.fake_tcp_header_raw_tcp_roundtrip` additionally captures real native
SYN/SYN-ACK/ACK and data through two raw peers, independently checks the
IPv4/fake-TCP/protocol-byte/native-TCP layout and both checksum layers, and
verifies cleanup.

The direct-TUN `waterwall.fake_tcp_header_mixed_packet_roundtrip` case separately
exercises TCP, UDP, ICMP and opaque protocol 253 on the same running pair in both
directions. This CTP/PTC case remains TCP-only because of its endpoints.
