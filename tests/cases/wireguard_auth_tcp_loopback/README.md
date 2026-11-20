# WireGuard authenticated TCP loopback

Normal TCP traffic enters ConnectionToPackets, crosses WireGuardClient and
UdpConnector, and is decrypted by WireGuardServer in connection mode. A separate
AuthenticationClient/AuthenticationServer service supplies the public key and inner
range. The private PTC/binding/UserController pipeline reaches TcpUdpConnector.
Run through the registered network namespace harness; endpoints are loopback only.
