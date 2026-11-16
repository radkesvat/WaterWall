<!--
Documentation version: 1
Sync note: Keep aligned with WaterWall-Docs/docs/02-noderefs/Ping6Client.mdx and its Persian translation.
-->

# Ping6Client Node

`Ping6Client` is the client-side endpoint of the Ping6 packet tunnel. It carries one complete inner IPv4 packet in an ICMPv6 Echo message inside an outer IPv4 packet with Protocol `58`. It does not require an IPv6 network on the tunnel path.

Use it opposite `Ping6Server`:

```text
TunDevice -> Ping6Client -> RawSocket
RawSocket -> Ping6Server -> TunDevice
```

Ping6 is not wire-compatible with `PingClient`/`PingServer`. Both peers must use Ping6.

## Data And Reply Model

Every local data packet becomes:

```text
20-byte outer IPv4 header
8-byte ICMPv6 Echo Request header (type 128, code 0)
Complete inner IPv4 packet
```

Data originated by either endpoint is always a new Echo Request. With `send-replies: true`, the receiving endpoint first sends an Echo Reply (`129`) with the same identifier, sequence, and Data. The default is `false`. Delivery never waits for a reply and new data is never placed in an unrelated reply.

| Input | Action |
| --- | --- |
| Upstream inner IPv4 | Encapsulate as Echo Request and forward upstream. |
| Downstream peer Echo Request | Optionally reply upstream; decapsulate and forward the inner IPv4 downstream once. |
| Downstream correlated Echo Reply | Consume as an acknowledgement. |
| Downstream unmatched reply or unrelated valid IPv4 | Forward unchanged downstream. |

## Configuration

```json
{
  "name": "ping6-client",
  "type": "Ping6Client",
  "settings": {
    "local-ipv4": "192.0.2.10",
    "peer-ipv4": "198.51.100.10",
    "send-replies": false,
    "identifier": "random",
    "sequence-start": 1,
    "ttl": 64,
    "tos": 0
  },
  "next": "raw-out"
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

Unknown settings are rejected. IPv4 values must be one plain dotted-quad address: four decimal fields without leading zeros. Explicit IPv6 values must be single addresses without brackets, zones, CIDR suffixes, or arrays. The IPv6 values are only a checksum context; they do not create routes or deliver packets to a real IPv6 host. A paired server normally reverses both local/peer pairs. When defaults are used, only the reversed IPv4 settings are needed.

The default pseudo-addresses come from each endpoint's own `local-ipv4`/`peer-ipv4`. If address translation makes the two endpoints see different outer IPv4 addresses, set `local-ipv6` and `peer-ipv6` explicitly on both sides; otherwise every carrier fails ICMPv6 checksum validation. The checksum covers the pair as a whole and does not change when the two values are swapped, so it cannot verify direction.

For RawSocket capture of this carrier, select `capture-protocols: [58]` with the appropriate peer source range.

## Checksums And Limits

The outer IPv4 header checksum and ICMPv6 checksum are independent. ICMPv6 uses its standard pseudo-header: source/destination IPv6 addresses, 32-bit message length, and Next Header `58`. There is no inner IPv6 header.

- Wrapper overhead is `28` bytes; maximum inner packet is `1472` bytes and maximum carrier is `1500` bytes.
- Local requests use configured IPv4 addresses/TOS/TTL, DF set, and IPv4 ID zero.
- Generated replies mirror identifier, sequence, and every inner byte; copy request TOS; use local TTL; clear fragmentation fields; and use the shared seeded reply-ID generator.
- Exact inner IPv4 fragments are preserved. Outer options and outer fragments are rejected.
- Incoming addressed carriers require matching tuples and valid IPv4/ICMPv6 checksums. Buffer-requested repair recalculates both checksums without modifying unrelated traffic.
- One node-wide tracker has bounded 1024-entry outstanding and replay rings. Replies and duplicate requests can match across worker lines; a duplicate request delivers its inner packet only once.
- Rejections are logged at `ERROR` level through a shared five-second rate limiter.

Ping6 provides no encryption, authentication, retransmission, PMTU discovery, TCP MSS adjustment, NDP, general ICMPv6 errors, direct IPv6-host delivery, or guaranteed DPI evasion.

## Examples

- [examples/client-tun](examples/client-tun/config.json): `TunDevice -> Ping6Client -> RawSocket` with TUN `10.58.0.1/30`.
- [server example](../Ping6Server/examples/server-tun/config.json): the peer, `RawSocket -> Ping6Server -> TunDevice` with TUN `10.58.0.2/30`.

Replace the documentation public addresses `192.0.2.10` and `198.51.100.10`, then run each side from its example directory with its `core.json`. The [examples guide](examples/README.md) covers requirements, verification, MTU, and multi-uplink hosts.

## Node Metadata

| Property | Value |
| --- | --- |
| `version` | `1` |
| node flags | `kNodeFlagNone` |
| `can_have_prev` / `can_have_next` | `true` / `true` |
| layer group (own/prev/next) | `kNodeLayer3` for all |
| `required_padding_left` | `28` bytes |
| line state | none |
