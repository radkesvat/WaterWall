Real AuthenticationClient/AuthenticationServer tables feed TrojanServer, VlessServer
and Socks5Server, each with a separate account limited to one simultaneous source IP.
Their owned UDP backends pass through automatically installed UserController admission
to real UdpConnector sockets and one namespace loopback echo target.

Each protocol opens two sessions from `127.0.0.2` and checks exact UDP round trips.
Attempts from `127.0.0.3` must not reach the target while both sessions remain or
after only the first closes. The remaining A session still forwards. Closing it
must allow a new B session to forward within five seconds. No specific refusal
reply is required. SOCKS uses separate dynamic endpoints with UDP sockets bound to
the same observed source as their TCP controls. VLESS uses one destination per
session. The probe closes all sockets; the existing runner checks orderly runtime
shutdown, including backend and dynamic endpoint drain.

The three CTest registrations are
`waterwall.{trojan,vless,socks5}server_udp_distinct_ip_probe`. They require Linux
network namespaces and the three servers, TcpListener, TcpUdpListener,
UdpConnector, AuthenticationClient and AuthenticationServer. They use one worker,
IPv4 namespace loopback only and no strace dependency. Native fixtures cover IPv6
source metadata separately.

Run the focused set with:

```bash
ctest --preset linux --output-on-failure -R 'server_udp_distinct_ip_probe$'
```

For a direct single-protocol run, set `WATERWALL_AUTH_UDP_PROTOCOL` to `trojan`,
`vless` or `socks5` before the usual namespace/probe runner invocation. Without
the variable the probe checks all three protocols.
