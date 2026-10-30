# Fake TCP header UDP roundtrip

Exercises UDP across the real `ConnectionToPackets` and `PacketsToConnection`
bridges, both FakeTcpHeader roles, and existing IpManipulator flag setters in
both directions. The packet path is directly connected inside one process;
this test needs no raw device and does not claim kernel capture coverage.

The existing SOCKS5 UDP entry supplies normal UDP associations. Each request
crosses client encode -> upstream flag setter -> downstream flag setter's node
-> server decode before reaching the backend UDP socket. Replies follow the
inverse chain with the downstream flag setter active. Different client/server
TCP options verify that receive header length comes from the packet.

The Tester pair exchanges nine payloads up to 1024 bytes per worker. The standard
namespace runner validates its all-workers success marker and shutdown status.
Use `ctest --preset linux -R '^waterwall\.fake_tcp_header_udp_roundtrip$'
--output-on-failure`. This deterministic test runs only on namespace loopback.

Real two-process protocol-6 capture, payload bytes, and unrelated-UDP delivery
are covered by `waterwall.fake_tcp_header_raw_roundtrip` in the privileged lane.
