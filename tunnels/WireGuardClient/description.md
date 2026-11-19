# WireGuardClient

WireGuardClient accepts inner IP packets on `prev` and exchanges encrypted
WireGuard datagrams on `next`. Return packets travel back toward `prev`.
Configure exactly one server peer. Keys use canonical Base64 encoding of 32 bytes:
44 characters with one trailing `=`.

```text
TunDevice -> WireGuardClient -> UdpConnector
TunDevice -> WireGuardClient -> JunkDatagramSender -> UdpConnector
TunDevice -> WireGuardClient -> UdpOverTcpClient -> TcpConnector
ConnectionToPackets -> WireGuardClient -> UdpConnector
```

ConnectionToPackets requires its own normal TCP/UDP input. Any compatible L3
producer may supply the client; TunDevice adjacency is not required.

```json
{
  "name": "vpn-client",
  "type": "WireGuardClient",
  "settings": {
    "privatekey": "0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=",
    "peers": [{
      "publickey": "GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=",
      "allowedips": "0.0.0.0/0",
      "endpoint": "vpn.example.com:51820",
      "persistentkeepalive": 25
    }]
  },
  "next": "udp"
}
```

For direct UDP transport, the UDP node uses `"type":"UdpConnector"` and settings
`{"address":"dest_context->address","port":"dest_context->port"}`. For junk,
point the client at a `JunkDatagramSender` node whose `next` is `udp`.

| Setting | Contract |
| --- | --- |
| `privatekey` | Required local private key. |
| `peers` | Exactly one peer object. |
| `publickey` | Required remote public key. |
| `allowedips` | Required comma-separated inner destination/remote source CIDRs, at most sixteen. |
| `endpoint` | Required initial destination: `host:port` or `[IPv6]:port`, port 1–65535. Subsequent nodes can select another endpoint through their normal settings. |
| `presharedkey` | Optional 32-byte Base64 PSK. |
| `persistentkeepalive` | Optional seconds, 0–65535; 0 disables persistent keepalives. |

Replace example keys for deployment. The node opens no OS interface. Configure
the TunDevice and OS routes separately.

One protocol engine and one owned normal carrier run on worker 0, sharing coherent
handshake, nonce and replay state across all input workers. Cross-worker work is
bounded to 512 messages and 8 MiB of retained allocation per node. The protocol
timer can send handshake datagrams after the next `Init` returns with the carrier
alive and writes permitted. The client processes replies from that exact carrier
before or after transport `Est`.

Until session keys are ready, a FIFO retains at most 128 inner packets and 1 MiB
of allocation. It flushes in order once the keys are ready. Overflow drops new
packets. An unavailable or paused carrier drops encrypted output. The protocol
timer retries handshakes. Shutdown recycles every retained inner packet.
Carrier creation attempts are separated by at least 400 ms.

The endpoint supplies the initial destination address, port and UDP protocol
before carrier Init. It does not override subsequent nodes' configured routing:
a connector or proxy can use `dest_context` or select its own transport endpoint.
The selected transport owns DNS resolution, socket selection and receive
filtering. When it finishes the carrier after a DNS or I/O failure, the client
can create another carrier through ordinary Init.

The chain must deliver one complete WireGuard message per payload callback in
both directions. UdpConnector is one option; no particular connector is required.
For a byte stream, use `UdpOverTcpClient` and a matching remote
`UdpOverTcpServer`. For example, a TCP relay can decode the framing and forward
datagrams to an ordinary WireGuard UDP server. A plain WireGuard UDP server
does not understand the TCP framing. The remote WireGuard public key still
authenticates the peer regardless of the selected transport.


Complete runnable core/config pairs are available in the
[WireGuard examples](https://github.com/radkesvat/WaterWall/tree/main/tunnels/WireGuardClient/examples).
