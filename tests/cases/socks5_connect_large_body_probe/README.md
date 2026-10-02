# socks5_connect_large_body_probe

## Execution and checks

Coalesced SOCKS CONNECT header plus a large application body, with auth/response and real echo peers. Exact negotiation/payload bytes and no lost tail; original unexpected-EOF policy. Runs inside the namespace harness.

Topology: auth-client: AuthenticationClient → auth-db; auth-db: AuthenticationServer; listener-noauth: TcpListener → socks-noauth; socks-noauth: Socks5Server → target-noauth; target-noauth: TcpConnector; listener-auth: TcpListener → socks-auth; socks-auth: Socks5Server → target-auth; target-auth: TcpConnector.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.socks5_connect_large_body_probe`.
