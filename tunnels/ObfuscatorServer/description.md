<!--
Documentation version: 154
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/ObfuscatorServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/ObfuscatorServer.mdx, and all files must keep the same documentation version.
-->

# ObfuscatorServer Node

`ObfuscatorServer` is the server-side peer of `ObfuscatorClient`. It restores upstream payload from the transport before forwarding to the next node, and encodes downstream replies before forwarding to the previous node.

The option-off path is stateless. TLS-like stream framing keeps normal-line receive state; exact packet lines remain stateless.

In practice, this node is used together with `ObfuscatorClient` configured with the same method and key.

Choose the role by the encoded side of the node: `ObfuscatorClient` faces its
transport at `next`; `ObfuscatorServer` faces its transport at the previous node.
A `Bridge` reverses callback direction, so two legs whose `next` sides face a
paired Bridge both use `ObfuscatorClient`.

## What It Does

- Reads payload from the previous node.
- Removes optional TLS-like framing and applies XOR before sending upstream plaintext to the next node.
- Applies XOR and adds optional TLS-like framing to downstream replies returning from the next node.
- Passes init, est, finish, pause, and resume events through unchanged.

In the current implementation, the only supported method is XOR.

## Typical Placement

A common layout is:

- transport-facing node before `ObfuscatorServer`
- `ObfuscatorServer`
- service-facing node after it

A typical TCP deployment uses `TcpListener -> ObfuscatorServer -> TcpConnector` on the server. The client uses `TcpListener -> ObfuscatorClient -> TcpConnector` and connects to that server listener.

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
  "next": "service-node"
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

- on the upstream receive path, it validates and strips the 5-byte TLS-like application-data header before XOR
- after XOR on the downstream reply path, it prepends that header
- the header bytes are `17 03 03` followed by the big-endian payload length

This only imitates the post-handshake TLS record shape. It is not a real TLS handshake or encryption layer.

### Event forwarding behavior

`ObfuscatorServer` forwards non-payload events in their original direction:

- upstream `init`, `est`, `finish`, `pause`, `resume`
- downstream `init`, `est`, `finish`, `pause`, `resume`

With TLS-like framing, normal stream Init initializes receive state and records the source side; Finish releases it.
Pause/Resume always relay transparently and do not gate encoding or decoding.

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
- Exact packet lines retain the one-packet/one-record limit and oversized-datagram drop policy.

## Node Metadata

Source-backed metadata:

This node explicitly disables splice for the entire chain through
`kNodeFlagBlocksSplice`, even if `kNodeFlagSupportsSplice` is also set.

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagBlocksSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayerAnything` |
| `layer_group_prev_node` | `kNodeLayerSameAsNext` |
| `layer_group_next_node` | `kNodeLayerSameAsPrev` |
| `required_padding_left` | `5` bytes |

With TLS-like framing enabled on ordinary streams, large deliveries split into
records of at most 65,535 body bytes, applying XOR and skip per record. One encoded
aggregate is sent per delivery. Receivers reassemble fragmented headers/bodies,
coalesce complete records into one onward callback, and retain partial tails.
Pause/Resume relay transparently, including repeats; complete records decode without waiting for Resume.
Incoming bytes plus any retained partial record are bounded by
a fixed **2,162,692 bytes** (`2 MiB + 65,540`), independent of pool sizes, RAM
profile and splice settings. The 65,535-byte record-body limit is separate. Malformed records
and overflow close the borrowed normal line, finishing the opposite side before the source side after local cleanup.
The nodes stay active to apply XOR and record processing to every payload. Packet behavior stays unchanged.
