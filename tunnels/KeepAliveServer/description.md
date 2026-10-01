<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/KeepAliveServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/KeepAliveServer.mdx, and all files must keep the same documentation version.
-->

# KeepAliveServer Node

`KeepAliveServer` is the peer tunnel for `KeepAliveClient`. It removes the same `5`-byte keepalive framing from
upstream traffic, forwards normal payload, and answers ping frames with pong frames.

The purpose of this tunnel is to periodically send/recv ping-pong messages that keep the connection appearing active, preventing timeout-based middleboxes (such as NAT devices and others) from closing it.

## Frame Format

Each frame starts with:

- `4` bytes: big-endian frame body length
- `1` byte: frame kind

Frame kinds are:

- `1`: normal payload
- `2`: ping
- `3`: pong

## Directional Behavior

- upstream payload is treated as a framed byte stream
- normal upstream frames are decoded and forwarded with `tunnelNextUpStreamPayload()`
- upstream `ping` frames are answered with downstream `pong` frames
- upstream `pong` frames are ignored
- downstream payload is encoded into framed output and sent with `tunnelPrevDownStreamPayload()`

## Finish Behavior

On either directional `Finish`, `KeepAliveServer`:

1. destroys its own per-line state
2. propagates the received directional finish

This keeps the close path aligned with Waterwall’s normal middle-tunnel directional finish rules.

## Configuration Example

```json
{
  "name": "keepalive-server",
  "type": "KeepAliveServer",
  "next": "next-node-name"
}
```

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `5` bytes |

## Splice Support

`KeepAliveServer` advertises `kNodeFlagSupportsSplice`. Its upstream decoder uses
a five-byte `splice_stream_t` header cache; its downstream encoder prepends the
same five-byte header in real left padding. Framing continues for the whole
connection, with payload bodies eligible for private-pipe forwarding. Payloads
larger than 6 MiB are split with representation-aware range operations.
Pipe allocation or capacity pressure may select complete ordinary fallback.
Pong control frames use ordinary buffers.

Nested encoder input stays behind the active payload under a shared 8 MiB
logical-byte and 1,024-buffer reentry bound, counting the active suffix. The decoder serializes nested input,
limits nested retained bytes to 8 MiB, and limits retained allocation charge to
16 MiB, attempting beneficial ordinary compaction before refusing excess charge.
Complete frames in an admitted delivery drain before checking the 6 MiB + 5 byte
incomplete-remainder limit. Pause is forwarded promptly and does not interrupt
that synchronous batch.

Zero or oversized frame body lengths, admission failure and retained-storage overflow
close the borrowed line through its owner. Finish releases incomplete frames,
active encoder suffixes and queued reentrant input; this node never destroys
`line_t` itself.
