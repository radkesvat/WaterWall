# socks5_connect_large_body_probe

## Execution and checks

This namespace probe checks coalesced SOCKS CONNECT and large application bodies with real echo peers. It also checks that a refused outbound dial closes the stream after CONNECT success in both authentication modes.

Topology: auth-client: AuthenticationClient → auth-db; auth-db: AuthenticationServer; listener-noauth: TcpListener → socks-noauth; socks-noauth: Socks5Server → target-noauth; target-noauth: TcpConnector; listener-auth: TcpListener → socks-auth; socks-auth: Socks5Server → target-auth; target-auth: TcpConnector.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socks5_connect_large_body_probe`.
