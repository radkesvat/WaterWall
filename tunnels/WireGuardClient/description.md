# WireGuardClient

## Overview

`WireGuardClient` accepts inner IP packets from `prev` and exchanges encrypted
WireGuard datagrams with one configured server peer on `next`. Decrypted return
packets go back toward `prev`.

Start with the [paired WireGuard packet-mode example](https://radkesvat.github.io/WaterWall-Docs/docs/examples/tunnels/wireguard)
for a TUN-to-TUN setup, or the [connection-mode example](https://radkesvat.github.io/WaterWall-Docs/docs/examples/tunnels/wireguard-connection)
for an account-backed IPv4 TCP/UDP exit. See [WireGuardServer](https://radkesvat.github.io/WaterWall-Docs/docs/noderefs/WireGuardServer)
for the server's mode and peer settings.

## Typical placement

```text
TunDevice -> WireGuardClient -> UdpConnector
TunDevice -> WireGuardClient -> JunkDatagramSender -> UdpConnector
TunDevice -> WireGuardClient -> UdpOverTcpClient -> TcpConnector
ConnectionToPackets -> WireGuardClient -> UdpConnector
```

Any compatible L3 source can supply `WireGuardClient`. A
[TunDevice](https://radkesvat.github.io/WaterWall-Docs/docs/noderefs/TunDevice) accepts packets from the OS. A
[ConnectionToPackets](https://radkesvat.github.io/WaterWall-Docs/docs/noderefs/ConnectionToPackets) needs a TCP/UDP connection
source and produces the inner IP packets itself.

The transport must deliver each WireGuard message in one complete payload
callback in both directions. Direct UDP uses [UdpConnector](https://radkesvat.github.io/WaterWall-Docs/docs/noderefs/UdpConnector). To send extra
outbound datagrams first, insert [JunkDatagramSender](https://radkesvat.github.io/WaterWall-Docs/docs/noderefs/JunkDatagramSender)
before the UDP connector. A TCP carrier needs a matching
[UdpOverTcpServer](https://radkesvat.github.io/WaterWall-Docs/docs/noderefs/UdpOverTcpServer) to recover the datagrams at the remote
relay before forwarding them to the WireGuard UDP listener. The configured
WireGuard public key authenticates the peer on every carrier.

## Minimal practical example

Node fragment for direct UDP. Define the node feeding inner packets and the
`udp` connector in the same configuration. Replace the example keys with your
own and set `endpoint` to the server's reachable UDP address.

```json
{
  "name": "vpn-client",
  "type": "WireGuardClient",
  "settings": {
    "privatekey": "0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=",
    "peers": [
      {
        "publickey": "GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=",
        "allowedips": "0.0.0.0/0",
        "endpoint": "vpn.example.com:51820",
        "persistentkeepalive": 25
      }
    ]
  },
  "next": "udp"
}
```

Set the `udp` node's type to `UdpConnector`, with `address` set to
`dest_context->address` and `port` set to `dest_context->port`. The client puts
the `endpoint` address, port, and UDP protocol in that destination context
before it initializes the transport. Later nodes can use the supplied address
or apply their own routing settings. The selected transport handles DNS, socket
selection, and receive filtering.

## Configuration

Set the top-level `type` to `WireGuardClient` and point `next` at the transport
path. Encode private keys, public keys, and preshared keys as canonical Base64
of 32 bytes, written as 44 characters ending in one `=`.

| Field in `settings` | Required | Description |
| --- | --- | --- |
| `privatekey` | Yes | Client's WireGuard private key. |
| `peers` | Yes | Array containing exactly one peer object. |
| `mtu` | No | Inner IP size in bytes up to which WireGuard may add padding. Integer from 68 to 65535. Defaults to the smaller of core `misc.mtu` and 1420. |

| Peer field | Required | Description |
| --- | --- | --- |
| `publickey` | Yes | Server's WireGuard public key. |
| `allowedips` | Yes | String with 1–16 comma-separated IPv4 or IPv6 CIDRs. These ranges select which inner destinations go to the peer and which inner source addresses are accepted from the peer. |
| `endpoint` | Yes | Initial transport destination in `host:port` or `[IPv6]:port` form, with a port from 1 to 65535. |
| `presharedkey` | No | Optional preshared key. For a static packet-mode peer, use the same value at both ends. WaterWall server connection mode uses no preshared key. |
| `persistentkeepalive` | No | Whole seconds from 0 to 65535. Defaults to `0`, which disables persistent keepalives. |

Before encryption, WireGuard rounds the inner IP packet length up to a multiple
of 16 bytes, capping the padding at `mtu` bytes of total plaintext. At or above
that size it encrypts the whole packet with zero added padding. Set the MTU of
the inner packet source and the WireGuard padding ceiling to leave room for
the carrier and WireGuard headers.
For example, on a 1500-byte path, direct UDP over IPv6 with a 40-byte IP
header leaves 1420 bytes for the inner packet. WireGuard uses the configured
ceiling without probing the path.

## Usage and troubleshooting

- **The handshake does not complete.** Verify the server's address and port,
  each peer's public key, and the preshared key if used. For TCP transport,
  point the TCP connector at the framing relay. A native WireGuard UDP
  listener does not decode the TCP framing.
- **The handshake works, but inner traffic does not pass.** Check that the
  destination matches the client's `allowedips` and that the server allows the
  client's inner source address. `WireGuardClient` creates no OS interface or
  routes. For a TUN setup, configure `TunDevice`, route the intended traffic
  into it, and keep the outer peer reachable outside the TUN route.

The [runnable WireGuard configuration files](https://github.com/radkesvat/WaterWall/tree/main/tunnels/WireGuardClient/examples)
include direct UDP, extra datagrams, and a TCP relay.

## Advanced behavior

The client retries handshakes and can reopen the carrier after a DNS or I/O
failure. Carrier creation attempts are spaced at least 400 ms apart. An
unavailable or paused carrier causes encrypted output to be dropped.

While waiting for a session key, the client queues up to 128 inner packets and
1 MiB of allocation. It drops new packets when the queue is full and drains
the queue in order once a key is ready. Shutdown releases any packets still
queued. Cross-worker packet work is limited to 512 messages and 8 MiB of
retained allocation per node.

See the developer guide for [carrier ownership and handshake timing](https://radkesvat.github.io/WaterWall-Docs/docs/devguides/part4-packet-tunnels#wireguard-authenticated-packet-to-connection-ownership)
and [worker shutdown](https://radkesvat.github.io/WaterWall-Docs/docs/devguides/part7-shutdown-and-signals#wireguard-worker-ownership-and-retirement).
