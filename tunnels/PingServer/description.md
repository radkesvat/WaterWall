# PingServer Node

`PingServer` is the server-side peer for `PingClient`. On the upstream path it applies the configured packet disguise logic toward the client side, and on the downstream path it reverses matching peer traffic back to plain packets.

It is a pure packet tunnel created with `packettunnelCreate()`, so it runs on the chain's worker packet lines and does not add per-line state.

## What It Does

- upstream applies the configured forward transform toward the client side
- downstream applies the reverse transform for ICMP packets coming from the client side and forwards unmatched packets unchanged
- downstream drops matching ICMP envelopes with malformed recovery metadata and logs the reason
- IPv4 packet strategies support IPv4 only
- any packet that an IPv4 packet strategy cannot safely rewrite is forwarded unchanged
- `xor-byte` and `roundup-size` only affect the ICMP envelope modes
- `identifier`, `check-identifier`, and `sequence-start` are only meaningful for the ICMP modes
- `ipv4-id-start`, `ttl`, and `tos` are only meaningful for the mode that creates a fresh outer IPv4 header

## `strategy`

### `wrap-in-new-ip-and-icmp-header`

- downstream expects:
  `outer IPv4 header -> ICMP echo header -> original IPv4 packet`
- upstream recreates that same envelope
- `source` and `dest` are optional in `settings`
- uses configured IPv4 addresses for the outer packet when provided
- when `source` or `dest` is omitted, that outer address is copied from the inner IPv4 packet
- does not verify configured source/destination addresses before decapsulation
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

## Example

```json
{
  "name": "icmp-server",
  "type": "PingServer",
  "settings": {
    "strategy": "wrap-in-new-ip-and-icmp-header",
    "identifier": 4660,
    "source": "203.0.113.20",
    "dest": "198.51.100.10",
    "xor-byte": 90,
    "roundup-size": true,
    "sequence-start": 0,
    "ttl": 64
  },
  "next": "tun-out"
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
