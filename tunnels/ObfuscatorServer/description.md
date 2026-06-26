<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/ObfuscatorServer.mdx, and both files must keep the same documentation version.
-->

# ObfuscatorServer Node

`ObfuscatorServer` is the server-side peer of `ObfuscatorClient`. It applies the same reversible payload transform in the same WaterWall callback directions as the client side: upstream payload is transformed before forwarding to the next node, and downstream payload is restored before forwarding to the previous node.

It is implemented as a stateless packet tunnel and does not keep per-line tunnel state.

In practice, this node is used together with `ObfuscatorClient` configured with the same method and key.

## What It Does

- Reads payload from the previous node.
- Applies the configured obfuscation method before sending payload to the next node.
- Applies the same operation again on downstream payload returning from the next node.
- Passes init, est, finish, pause, and resume events through unchanged.

In the current implementation, the only supported method is XOR.

## Typical Placement

A common layout is:

- service-facing packet node before `ObfuscatorServer`
- `ObfuscatorServer`
- transport-facing node after it

It should usually sit opposite `ObfuscatorClient`. With a `Bridge` pair, upstream traffic from `ObfuscatorClient` arrives at `ObfuscatorServer` through the server's downstream callback, so the server strips the TLS-like header there.

## Configuration Example

```json
{
  "name": "obfuscator-server",
  "type": "ObfuscatorServer",
  "settings": {
    "method": "xor",
    "xor_key": 90,
    "skip": "transport",
    "tls_record_header": true
  },
  "next": "transport-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"ObfuscatorServer"`.

- `next` `(string)`
  The next node that should receive the upstream transformed payload.

### `settings`

- `method` `(string)`
  Obfuscation method to use.

  Currently supported values:
  - `"xor"`

- `xor_key` `(integer)`
  Required when `method` is `"xor"`.

  This value is converted to a single byte and used as the XOR key.

- `tls_record_header` `(boolean)`
  Optional.

  When `true`, the transport-facing payload is wrapped in a minimal TLS application-data record header:
  content type `23`, version `0x0303`, and a 2-byte payload length.

- `skip` `(string)`
  Optional.

  Controls which leading packet bytes are left unobfuscated before XOR runs.

  Supported values:
  - `"none"`: XOR the whole payload buffer
  - `"ipv4"`: if the payload starts with a valid IPv4 packet, leave only the IPv4 header clear
  - `"transport"`: if the payload starts with a valid IPv4 TCP/UDP packet, leave the IPv4 header and the TCP/UDP header clear

## Optional `settings` Fields

There are no additional tunnel-specific optional settings in the current implementation beyond `tls_record_header` and `skip`.

## Detailed Behavior

### XOR behavior

For each payload buffer:

- before sending upstream to the next node, payload bytes after the configured skip region are XORed with `xor_key`
- when payload comes back downstream, payload bytes after the configured skip region are XORed with the same `xor_key` again

Because XOR is symmetrical, the same code path is valid for obfuscation and de-obfuscation.

When `skip` is enabled and the payload does not parse as a valid IPv4 packet, the tunnel falls back to XORing the whole payload buffer.

### Optional TLS-like record header

When `tls_record_header` is enabled:

- after XOR on the upstream send path, the tunnel prepends a 5-byte TLS-like application-data header
- on the downstream receive path, it validates and strips that same 5-byte header before XOR
- the header bytes are `17 03 03` followed by the big-endian payload length

This only imitates the post-handshake TLS record shape. It is not a real TLS handshake or encryption layer.

### Event forwarding behavior

`ObfuscatorServer` forwards all non-payload events without adding protocol or buffering of its own:

- upstream `init`, `est`, `finish`, `pause`, `resume`
- downstream `init`, `est`, `finish`, `pause`, `resume`

Only payload bytes are transformed.

### Implementation details

Like the client side, the server-side XOR helper uses optimized chunked implementations when possible:

- AVX2 when available
- 64-bit aligned processing when possible
- 32-bit or byte-wise fallback otherwise

This is a performance detail only.

## Notes And Caveats

- `ObfuscatorServer` is intended to be paired with `ObfuscatorClient` using the same `method` and `xor_key`.
- Current support is limited to `method: "xor"`.
- This tunnel does not provide cryptographic protection.
- `xor_key` is stored as a single byte in the current implementation, so values outside `0..255` are effectively truncated.
- When `tls_record_header` is enabled, a single payload buffer must fit in one TLS-style record, so payloads larger than `65535` bytes are dropped.
