# Trojan UDP size boundaries

Runs real UdpListener -> TrojanClient -> TlsClient -> TcpConnector and
TcpListener -> TlsServer -> TrojanServer -> UdpConnector chains on isolated
IPv4 loopback. The probe sends exact 0, 1, 8191, 8192, 8193, 32768, 65400 and
65507-byte datagrams and compares complete payloads in both directions.
Request/reply sizes differ, including a one-byte request with a 65507-byte reply,
so the server/client size asymmetry cannot be hidden by an echo-only workload.
A distinct, bounded readiness exchange handles UDP admission during the TLS
handshake. Every measured datagram is sent exactly once; readiness-token residue
cannot be mistaken for measured traffic.

65507 is the ordinary IPv4 UDP payload maximum; the native Trojan units cover
the 65535-byte framing maximum and reject 65536-byte local payloads. No datagram
is split or truncated. TLS uses the existing local fixture certificate and
explicitly disables client verification; this case tests framing, not trust setup.

CTest: `waterwall.trojan_udp_size_probe`. The existing probe runner owns startup,
the 25-second deadline, artifact retention and orderly shutdown. No public DNS
or host-network port availability is used.
