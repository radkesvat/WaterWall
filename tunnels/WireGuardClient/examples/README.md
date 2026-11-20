# WireGuard examples

Each directory contains a complete core.json and config.json. Run Waterwall
from that directory. TUN examples need the normal TunDevice privileges. Replace
all sample private keys, account passwords and service secrets for deployment.

- `client`: TunDevice → WireGuardClient → UdpConnector.
- `client-junk`: adds three outbound junk datagrams to that path.
- `client-tcp`: TunDevice → WireGuardClient → UdpOverTcpClient → TcpConnector.
- `relay-tcp`: TcpListener → UdpOverTcpServer → UdpConnector; unwraps the TCP
  framing and forwards WireGuard datagrams to either server below.
- `packet-server`: UdpListener → WireGuardServer(packet) → TunDevice.
- `connection-server`: UdpListener → WireGuardServer(connection) → TcpUdpConnector;
  AuthenticationClient is a separate service connected to the local example
  AuthenticationServer. Production can use its ordinary remote control transport.

Choose one client and one server. For `client` or `client-junk`, set the
WireGuard endpoint to the server's reachable UDP address; the examples use
loopback port 51820. For `client-tcp`, also run `relay-tcp`: its TcpConnector
selects loopback port 51821, overriding the WireGuard endpoint's initial
51820 destination. The relay listens on TCP port 51821 and sends decoded
datagrams to UDP port 51820. For separate hosts, configure the TCP connector
with the relay's address and the relay's UDP connector with the WireGuard
server's address. A plain WireGuard UDP server cannot accept the TCP framing.

All clients use the same sample key, Base64(SHA256("wireguard-user-secret")),
matching the connection server's users.json. The packet server authorizes the
same public key statically.

The client TUN address is 10.50.0.5; the packet server TUN address is 10.50.0.1.
Configure routes for the intended inner destinations using the OS's ordinary
network administration. Packet-server forwarding/NAT is also an OS decision.
The connection server opens normal TCP/UDP connections to inner destinations;
it supports unfragmented IPv4 TCP/UDP and needs no server TUN or NAT.

WireGuardClient supplies its endpoint as the initial destination; the remaining
nodes apply their ordinary routing, DNS and receive-filtering behavior. The chain
must preserve each WireGuard datagram in both directions. Optional PSK is
supported by the client and static packet server; connection mode rejects PSK
configuration.
With IP limit 1, multiple connections from 10.50.0.5 share one slot; 10.50.0.6 is
refused until the last connection or UDP association from .5 closes/expires.
