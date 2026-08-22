<!--
Documentation version: 152
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/PingClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/PingClient.mdx, and all files must keep the same documentation version.
-->

# PingClient Node

`PingClient` is a layer-3 packet tunnel. On the upstream path it transforms IPv4 packets according to a configured ICMP-related strategy, and on the downstream path it applies the inverse logic for the matching peer traffic.

It is a pure packet tunnel created with `packettunnelCreate()`, so it does not create per-connection line state and it works on the worker packet lines supplied by the chain.

Direct `PingClient -> PingServer` adjacency is the canonical pair. PingClient wraps
the upstream request and PingServer restores it in its upstream callback before
continuing to the next node. On the return path, PingServer wraps the downstream
response and PingClient restores it in its downstream callback.

Typical deployment order is:

```text
TunDevice -> PingClient -> RawSocket
RawSocket -> PingServer -> TunDevice
```

## Compatibility And Migration

This direction change is intentionally breaking for old PingServer topologies.
The client order above is unchanged, but an existing
`TunDevice -> PingServer -> RawSocket` server chain must become
`RawSocket -> PingServer -> TunDevice`. Replace paired-Bridge Ping layouts with
direct `PingClient -> PingServer` adjacency. The PingClient implementation,
settings, and wire format are unchanged, so an older PingClient remains
wire-compatible with the new PingServer when their settings match. The strict
requirement is to deploy the new PingServer binary together with the new server
topology; an old PingServer needs the old server topology. Upgrading both peers
together can still simplify operations, but it is not required by the protocol.
MTU requirements remain strategy-dependent.

## What It Does

- upstream uses one of four JSON-controlled strategies
- downstream reverses that strategy for matching ICMP packets and forwards unmatched packets unchanged
- downstream drops matching ICMP envelopes with malformed recovery metadata and logs the reason
- IPv4 packet strategies support IPv4 only
- any packet that an IPv4 packet strategy cannot safely rewrite is forwarded unchanged
- `xor-byte` still applies only to the ICMP payload modes
- `roundup-size` still applies only to the ICMP payload modes
- `identifier`, `check-identifier`, and `sequence-start` are only meaningful for the ICMP modes
- `ipv4-id-start`, `ttl`, and `tos` are only meaningful for the mode that creates a fresh outer IPv4 header

## `strategy`

### `wrap-in-new-ip-and-icmp-header`

- wraps the whole inner IPv4 packet as:
  `new outer IPv4 header -> ICMP echo header -> original IPv4 packet`
- `source` and `dest` are optional in `settings`
- uses configured IPv4 addresses for the outer packet when provided
- when `source` or `dest` is omitted, that outer address is copied from the inner IPv4 packet
- on decapsulation, configured source/destination addresses are not verified
- accepts ICMP echo requests and echo replies with the configured identifier
- if `check-identifier` is enabled, ICMP echo traffic with a mismatched identifier is warned and forwarded unchanged
- after a matching ICMP envelope is found, the payload is stripped and forwarded even if the recovered bytes are not a valid IPv4 packet

### `wrap-in-icmp-header-and-reuse-ipv4-addresses`

- reuses the packet's existing IPv4 header instead of creating a new outer IPv4 header
- does not ask for `source` or `dest`
- keeps source, destination, TOS, TTL, IPv4 ID, DF flag, and IPv4 options from the current packet
- changes the existing IPv4 protocol field to `ICMP`
- inserts an ICMP echo header after the existing IPv4 header
- places the original transport bytes in the ICMP payload
- appends a small metadata trailer as the last bytes of the ICMP payload
- metadata stores the original IPv4 protocol number and original transport length so the peer can restore the packet
- forwards fragmented IPv4 packets unchanged because this mode cannot restore them safely
- forwards packets unchanged when the ICMP-wrapped size would exceed `kMaxAllowedPacketLength`

### `wrap-in-only-icmp-header`

- treats input as raw bytes, not as an IPv4 packet
- prepends only an ICMP echo header
- emits `ICMP echo header -> raw payload`
- does not emit an IPv4 header
- does not ask for `source` or `dest`
- unwraps matching ICMP frames back to the original raw bytes
- output is not a complete IP packet, but it is valid ICMP frame data

### `change-only-ipv4-protocol-number`

- does not add an ICMP header and does not prepend a new IPv4 header
- only swaps the IPv4 protocol number in place
- requires `swap-protocol`
- upstream changes packets whose current IPv4 protocol matches `swap-protocol` into `ICMP`
- downstream changes matching `ICMP` packets back to `swap-protocol`
- recalculates the IPv4 header checksum immediately and leaves transport bytes unchanged
- this mode does not use `identifier`, `sequence-start`, `ipv4-id-start`, `xor-byte`, or `roundup-size`

`swap-protocol` accepts:

- `"TCP"`
- `"UDP"`
- `"ICMP"`
- an integer protocol number between `0` and `255`

## Optional `settings`

- `strategy` `(string)`
  Controls packet transformation mode.
  Default: `wrap-in-icmp-header-and-reuse-ipv4-addresses`

- `identifier` `(integer)`
  ICMP echo identifier for the ICMP envelope modes.
  Range: `0..65535`
  Default: `44975` (`0xAFAF`)

- `check-identifier` `(boolean)`
  Requires downstream ICMP envelope packets to match `identifier`.
  Set to `false` only when the peer intentionally uses a different ICMP identifier.
  Default: `true`

- `sequence-start` `(integer)`
  Initial ICMP echo sequence counter for the ICMP envelope modes.
  Range: `0..65535`
  Default: `0`

- `ipv4-id-start` `(integer)`
  Initial outer IPv4 identification counter for `wrap-in-new-ip-and-icmp-header`.
  Range: `0..65535`
  Default: `0`

- `ttl` `(integer)`
  Default outer IPv4 TTL for `wrap-in-new-ip-and-icmp-header`.
  Range: `0..255`
  Default: `64`

- `tos` `(integer)`
  Default outer IPv4 TOS byte for `wrap-in-new-ip-and-icmp-header`.
  Range: `0..255`
  Default: `0`

- `xor-byte` `(integer)`
  XOR byte applied only to the ICMP payload in the ICMP envelope modes.
  Range: `0..255`

- `roundup-size` `(boolean)`
  Pads only the ICMP payload in the ICMP envelope modes.
  Default: `false`

- `source` `(string)`
  Optional for `wrap-in-new-ip-and-icmp-header`.
  When omitted, the outer source is copied from the inner IPv4 packet.
  When provided, it must be a single IPv4 address.

- `dest` `(string)`
  Optional for `wrap-in-new-ip-and-icmp-header`.
  When omitted, the outer destination is copied from the inner IPv4 packet.
  When provided, it must be a single IPv4 address.

- `swap-protocol` `(string or integer)`
  Required only when `strategy` is `change-only-ipv4-protocol-number`.
  Numeric range: `0..255`

## MTU And Packet-Size Limits

**Warning:** `PingClient` does not fragment packets, discover the path MTU, or
reduce an upstream TCP MSS. Its size checks use the compile-time
`kMaxAllowedPacketLength`, currently `1500` bytes; they do not use `misc.mtu`.
`misc.mtu` only becomes relevant here when another node, such as `TunDevice`,
uses it as an input MTU default.

At the current 1500-byte Ping limit, the largest input that each strategy can
transform is:

| Strategy | Minimum added bytes | Maximum input, `roundup-size=false` | Maximum input, `roundup-size=true` |
| --- | ---: | ---: | ---: |
| `wrap-in-new-ip-and-icmp-header` | 28-byte outer IPv4 + ICMP headers | 1472 | 1470 |
| `wrap-in-icmp-header-and-reuse-ipv4-addresses` | 8-byte ICMP header + 5-byte trailer | 1487 | 1487 |
| `wrap-in-only-icmp-header` | 8-byte ICMP header | 1492 | 1490 |
| `change-only-ipv4-protocol-number` | 0 | 1500 | not applicable |

The ICMP-only row measures its raw input and output frame; this strategy does
not emit an IP header.

When a valid input exceeds the applicable limit, the current ICMP envelope
strategies normally forward the original packet unchanged instead of
fragmenting or wrapping it. This is not a safe substitute for MTU planning: the
packet is no longer disguised as the configured ICMP envelope and may be
filtered or routed differently.

For a common `TunDevice -> PingClient -> RawSocket` path whose real packet MTU
is 1500, configure `TunDevice.settings.device-mtu` no higher than the applicable
table value. Setting both `misc.mtu` and `device-mtu` to `1400` is a simple
conservative choice when the Ping strategy may change, but it is not required
when the exact overhead is known.

`roundup-size` can pad an accepted packet all the way to the 1500-byte Ping
limit. Consequently, a 1400-byte input is safe for a direct 1500-byte output
path, but roundup may consume the remaining space; it does not necessarily
leave 100 bytes for another encapsulation layer after `PingClient`. Account for
every later header as well, and use the smaller of the real path MTU and every
downstream node's packet limit.

## Example

```json
{
  "name": "icmp-client",
  "type": "PingClient",
  "settings": { 
    "strategy": "wrap-in-new-ip-and-icmp-header",
    "identifier": 4660,
    "source": "198.51.100.10",
    "dest": "203.0.113.20",
    "xor-byte": 90,
    "roundup-size": true,
    "sequence-start": 0,
    "ttl": 64
  },
  "next": "raw-out"
}
```

## Notes

- `settings` may be omitted or empty; defaults are used when possible
- `required_padding_left` remains `28` bytes so the tunnel can prepend the worst-case IPv4 plus ICMP envelope safely
- ICMP payload modes forward packets unchanged when added bytes would exceed `kMaxAllowedPacketLength`
- fragmented outer ICMP packets are not decapsulated here
- unmatched IPv4 traffic is still forwarded unchanged in the same direction
- IPv4 packet strategies forward packets unchanged when they cannot safely rewrite them; `wrap-in-only-icmp-header` treats input as raw bytes
- legacy aliases such as `warp-*`, `warp-in-icmp-header-and-update-ipv4-header`, `change-only-ip4-packet-identifier-number`, and `swap-identifier` are still accepted for backward compatibility

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` |
| `layer_group_prev_node` | `kNodeLayer3` |
| `layer_group_next_node` | `kNodeLayer3` |
| `required_padding_left` | `28` bytes |
