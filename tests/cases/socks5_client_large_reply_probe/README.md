# socks5_client_large_reply_probe

## Execution and checks

Large SOCKS reply extension fields are consumed before the application response. Fixed loopback peers and fragmented control reads; exact bytes/EOF, with the original unexpected-EOF failure policy.

Topology: listener-noauth: TcpListener → socks-noauth; socks-noauth: Socks5Client → connector-noauth; connector-noauth: TcpConnector; listener-auth: TcpListener → socks-auth; socks-auth: Socks5Client → connector-auth; connector-auth: TcpConnector.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socks5_client_large_reply_probe`.
