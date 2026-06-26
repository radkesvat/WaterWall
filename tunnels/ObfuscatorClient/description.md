<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/obfs-client.mdx, and both files must keep the same documentation version.
-->

# ObfuscatorClient Node

`ObfuscatorClient` applies a reversible payload transform to traffic passing through it. In the current implementation, the only supported method is XOR obfuscation.

It is implemented as a stateless packet tunnel and does not keep per-line tunnel state.

In practice, this node is used together with `ObfuscatorServer` configured with the same method and key.

## What It Does

- Reads payload from the previous node.
- Applies the configured obfuscation method before sending payload to the next node.
- Applies the same operation again on downstream payload returning from the next node.
- Forwards all init, est, finish, pause, and resume events without changing their meaning.

Because XOR is symmetrical, the same transform is used in both directions.

## Typical Placement

A common layout is:

- normal payload-producing node before `ObfuscatorClient`
- `ObfuscatorClient`
- some transport path
- `ObfuscatorServer` on the remote side
- service-facing nodes after it

This tunnel is useful only as a lightweight payload obfuscation layer. It is not a secure encryption layer.

## Configuration Example

```json
{
  "name": "obfuscator-client",
  "type": "ObfuscatorClient",
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
  Must be exactly `"ObfuscatorClient"`.

- `next` `(string)`
  The next node that should receive the transformed payload.

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

Because XOR is reversible, both ends must use the same key.

When `skip` is enabled and the payload does not parse as a valid IPv4 packet, the tunnel falls back to XORing the whole payload buffer.

### Optional TLS-like record header

When `tls_record_header` is enabled:

- after XOR on the transport-facing send path, the tunnel prepends a 5-byte TLS-like application-data header
- on the transport-facing receive path, it validates and strips that same 5-byte header before XOR
- the header bytes are `17 03 03` followed by the big-endian payload length

This only imitates the post-handshake TLS record shape. It is not a real TLS handshake or encryption layer.

### Event forwarding behavior

`ObfuscatorClient` does not change line ownership or connection topology.

It simply forwards:

- upstream `init`, `est`, `finish`, `pause`, `resume`
- downstream `init`, `est`, `finish`, `pause`, `resume`

Only payload is modified.

### Implementation details

The XOR helper is optimized for the current platform:

- AVX2 path when available
- 64-bit chunked path on aligned 64-bit builds
- 32-bit chunked or byte-by-byte fallback otherwise

That optimization affects speed only, not the visible behavior.

## Notes And Caveats

- `ObfuscatorClient` is intended to be paired with `ObfuscatorServer` using the same `method` and `xor_key`.
- Current support is limited to `method: "xor"`.
- This is obfuscation, not cryptographic security.
- `xor_key` is stored as a single byte in the current implementation, so values outside `0..255` are effectively truncated.
- When `tls_record_header` is enabled, a single payload buffer must fit in one TLS-style record, so payloads larger than `65535` bytes are dropped.
