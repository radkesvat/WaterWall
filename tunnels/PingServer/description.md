# PingServer Node

`PingServer` is the server-side peer for `PingClient`. On the upstream path it reverses the configured packet disguise logic, and on the downstream path it reapplies the matching strategy toward the client side.

It is a pure packet tunnel created with `packettunnelCreate()`, so it runs on the chain's worker packet lines and does not add per-line state.

## What It Does

- upstream applies the configured reverse transform for packets coming from the client side
- downstream applies the forward transform toward the client side
- IPv4 packet strategies support IPv4 only
- any IPv6 packet that reaches an IPv4 packet strategy is logged and dropped
- `xor-byte` and `roundup-size` only affect the ICMP envelope modes
- `identifier` and `sequence-start` are only meaningful for the ICMP modes
- `ipv4-id-start`, `ttl`, and `tos` are only meaningful for the mode that creates a fresh outer IPv4 header

## `strategy`

### `wrap-in-new-ip-and-icmp-header`

- upstream expects:
  `outer IPv4 header -> ICMP echo header -> original IPv4 packet`
- downstream recreates that same envelope
- requires both `source` and `dest` in `settings`
- verifies the configured outer source and destination before decapsulation
- if ICMP framing and identifier match but source or destination does not, `PingServer` logs a runtime warning and leaves the packet unchanged for the next node
- source/destination verification accepts both the configured direction and the reversed direction

### `wrap-in-icmp-header-and-reuse-ipv4-addresses`

- reuses the packet's existing IPv4 header instead of creating a new outer IPv4 header
- does not ask for `source` or `dest`
- keeps source, destination, TOS, TTL, IPv4 ID, DF flag, and IPv4 options from the current packet
- changes the existing IPv4 protocol field to `ICMP`
- inserts an ICMP echo header after the existing IPv4 header
- places the original transport bytes in the ICMP payload
- appends a small metadata trailer as the last bytes of the ICMP payload
- metadata stores the original IPv4 protocol number and original transport length so the peer can restore the packet
- drops fragmented IPv4 packets because this mode cannot restore them safely
- drops packets whose ICMP-wrapped size would exceed `kMaxAllowedPacketLength`

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
- downstream changes packets whose current IPv4 protocol matches `swap-protocol` into `ICMP`
- upstream changes matching `ICMP` packets back to `swap-protocol`
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
  Default: `44975` (`0xAFAF`)

- `sequence-start` `(integer)`
  Initial ICMP echo sequence counter for the ICMP envelope modes.
  Default: `0`

- `ipv4-id-start` `(integer)`
  Initial outer IPv4 identification counter for `wrap-in-new-ip-and-icmp-header`.
  Default: `0`

- `ttl` `(integer)`
  Default outer IPv4 TTL for `wrap-in-new-ip-and-icmp-header`.
  Default: `64`

- `tos` `(integer)`
  Default outer IPv4 TOS byte for `wrap-in-new-ip-and-icmp-header`.
  Default: `0`

- `xor-byte` `(integer)`
  XOR byte applied only to the ICMP payload in the ICMP envelope modes.

- `roundup-size` `(boolean)`
  Pads only the ICMP payload in the ICMP envelope modes.
  Default: `false`

- `source` `(string)`
  Required only when `strategy` is `wrap-in-new-ip-and-icmp-header`.
  Must be a single IPv4 address.

- `dest` `(string)`
  Required only when `strategy` is `wrap-in-new-ip-and-icmp-header`.
  Must be a single IPv4 address.

- `swap-protocol` `(string or integer)`
  Required only when `strategy` is `change-only-ipv4-protocol-number`.

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
- ICMP payload modes drop packets when added bytes would exceed `kMaxAllowedPacketLength`
- fragmented outer ICMP packets are not decapsulated here
- unmatched IPv4 traffic is still forwarded unchanged in the same direction
- IPv6 is dropped by the IPv4 packet strategies; `wrap-in-only-icmp-header` treats input as raw bytes
- legacy aliases such as `warp-*`, `warp-in-icmp-header-and-update-ipv4-header`, `change-only-ip4-packet-identifier-number`, and `swap-identifier` are still accepted for backward compatibility
