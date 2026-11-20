# WireGuard authenticated UDP loopback

Normal UDP traffic enters ConnectionToPackets, crosses WireGuardClient and
UdpConnector, and is decrypted by WireGuardServer in connection mode. A separate
AuthenticationClient/AuthenticationServer service supplies the public key and inner
range. The private PTC/binding/UserController pipeline reaches TcpUdpConnector.
Run through the registered network namespace harness; endpoints are loopback only.

The four workers send 40 initial datagrams in total, within the documented
128-packet initial client FIFO. Payloads include 1–4096-byte chunks split into
1024-byte datagrams; the test does not require lossless admission above that bound.
