<!--
Documentation version: 1
Sync note: Keep aligned with WaterWall-Docs/docs/02-noderefs/Ping6Server.mdx and its Persian translation.
-->

# Ping6Server Node

`Ping6Server` is the server-side endpoint of the Ping6 packet tunnel. It carries one complete inner IPv4 packet in an ICMPv6 Echo message inside an outer IPv4 packet with Protocol `58`. No IPv6 network is required between the endpoints.

Use it opposite `Ping6Client`:

```text
TunDevice -> Ping6Client -> RawSocket
RawSocket -> Ping6Server -> TunDevice
```

Ping6 is not wire-compatible with `PingClient`/`PingServer`; both peers must use Ping6.

## Data, Direction, And Replies

Every local data packet uses an outer IPv4 header, an ICMPv6 Echo Request header (`128`, code `0`), and one complete inner IPv4 packet. Opposite-direction data is always a fresh request. With `send-replies: true`, the receiver first returns an Echo Reply (`129`) containing the exact request identifier, sequence, and Data. The default is `false`; delivery does not wait for acknowledgements.

| Input | Action |
| --- | --- |
| Upstream peer Echo Request | Optionally reply downstream; decapsulate and forward the inner IPv4 upstream once. |
| Upstream correlated Echo Reply | Consume as an acknowledgement. |
| Upstream unmatched reply or unrelated valid IPv4 | Forward unchanged upstream. |
| Downstream inner IPv4 | Encapsulate as Echo Request and forward downstream. |

Decoded data uses `tunnelNextUpStreamPayload()`. Generated replies and server-originated requests use `tunnelPrevDownStreamPayload()`.

## Configuration

```json
{
  "name": "ping6-server",
  "type": "Ping6Server",
  "settings": {
    "local-ipv4": "198.51.100.10",
    "peer-ipv4": "192.0.2.10",
    "send-replies": false,
    "identifier": "random",
    "sequence-start": 1,
    "ttl": 64,
    "tos": 0
  },
  "next": "tun-in"
}
```

| Setting | Required | Default | Meaning |
| --- | --- | --- | --- |
| `local-ipv4` | yes | — | Local carrier source and expected inbound destination. |
| `peer-ipv4` | yes | — | Carrier destination and expected inbound source. |
| `local-ipv6` | no | `::ffff:<local-ipv4>` | Pseudo-header source for locally generated ICMPv6 messages. |
| `peer-ipv6` | no | `::ffff:<peer-ipv4>` | Pseudo-header destination for locally generated ICMPv6 messages. |
| `identifier` | no | `"random"` | Local request identifier; nonzero random for node lifetime or integer `0..65535`. |
| `sequence-start` | no | `1` | First local request sequence, integer `0..65535`; wrap is valid. |
| `ttl` | no | `64` | Outer IPv4 TTL, integer `0..255`. |
| `tos` | no | `0` | TOS for local requests, integer `0..255`; replies copy request TOS. |
| `send-replies` | no | `false` | Send exact Echo Replies to peer requests when true. |

Unknown settings are rejected. IPv4 values must be one plain dotted-quad address: four decimal fields without leading zeros. Explicit IPv6 values must be single addresses without brackets, zones, CIDR suffixes, or arrays. They are used only for the ICMPv6 checksum pseudo-header and do not configure an IPv6 adapter or route. The paired client normally reverses both local/peer pairs; with defaults, only reversed IPv4 settings are necessary.

The default pseudo-addresses come from each endpoint's own `local-ipv4`/`peer-ipv4`. If address translation makes the two endpoints see different outer IPv4 addresses, set `local-ipv6` and `peer-ipv6` explicitly on both sides; otherwise every carrier fails ICMPv6 checksum validation. The checksum covers the pair as a whole and does not change when the two values are swapped, so it cannot verify direction.

For RawSocket capture, select `capture-protocols: [58]` with the client's source address range.

## Validation, Checksums, And Limits

ICMPv6 checksum covers the complete Echo message plus the standard pseudo-header containing the configured IPv6 source/destination, 32-bit message length, and Next Header `58`. The outer IPv4 checksum is calculated separately. There is no inner IPv6 header.

- The wrapper is `28` bytes. Inner IPv4 is limited to `1472` bytes and the carrier to `1500` bytes.
- Local requests use configured IPv4 addresses/TOS/TTL, DF set, and IPv4 ID zero. Replies copy request TOS, identifier, sequence, and inner bytes; use local TTL; clear fragmentation fields; and use the shared seeded reply-ID generator.
- Inner IPv4 fragments retain their exact bytes and boundaries. Outer options and fragments are rejected.
- Addressed inbound carriers require matching tuples and valid IPv4/ICMPv6 checksums. Buffer-requested repair recalculates both checksums without changing unrelated packets.
- Bounded node-wide 1024-entry outstanding and replay rings work across worker lines. Duplicate requests deliver the inner packet only once and may receive another optional reply.
- Rejections use `ERROR` network logs with a shared five-second rate limiter.

Ping6 provides no encryption, authentication, retransmission, PMTU discovery, TCP MSS adjustment, NDP, general ICMPv6 errors, direct IPv6-host delivery, or guaranteed DPI evasion.

## Examples

- [examples/server-tun](examples/server-tun/config.json): `RawSocket -> Ping6Server -> TunDevice` with TUN `10.58.0.2/30`.
- [client example](../Ping6Client/examples/client-tun/config.json): the peer, `TunDevice -> Ping6Client -> RawSocket` with TUN `10.58.0.1/30`.

Replace the documentation public addresses `192.0.2.10` and `198.51.100.10`, then run each side from its example directory with its `core.json`. The [examples guide](../Ping6Client/examples/README.md) covers requirements, verification, MTU, and multi-uplink hosts.

## Node Metadata

| Property | Value |
| --- | --- |
| `version` | `1` |
| node flags | `kNodeFlagNone` |
| `can_have_prev` / `can_have_next` | `true` / `true` |
| layer group (own/prev/next) | `kNodeLayer3` for all |
| `required_padding_left` | `28` bytes |
| line state | none |
