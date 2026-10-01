<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/KeepAliveClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/KeepAliveClient.mdx, and all files must keep the same documentation version.
-->

# KeepAliveClient Node

`KeepAliveClient` is a small framing tunnel that wraps upstream payloads with a `5`-byte keepalive header and
periodically sends ping control frames on every live borrowed line it tracks.

The purpose of this tunnel is to periodically send/recv ping-pong messages that keep the connection appearing active, preventing timeout-based middleboxes (such as NAT devices and others) from closing it.

This tunnel must reach KeepAliveServer for it to work.


It is designed to compose like other Waterwall middle tunnels. It does not invent a new line lifecycle and it does not
hold protocol state alive after a clean finish.

## Frame Format

Each transmitted frame starts with:

- `4` bytes: big-endian frame body length
- `1` byte: frame kind

Frame body length includes the `1`-byte frame kind plus any payload bytes. Each
frame carries at most `6 MiB` of payload. Body lengths outside `1..6,291,457`
close the line. Both peers use the same five-byte prefix.

Frame kinds are:

- `1`: normal payload
- `2`: ping
- `3`: pong

## Directional Behavior

- upstream payload is encoded into framed output and sent with `tunnelNextUpStreamPayload()`
- downstream payload is treated as a byte stream of framed input
- normal downstream frames are decoded and forwarded with `tunnelPrevDownStreamPayload()`
- downstream `ping` frames are answered with upstream `pong` frames
- downstream `pong` frames are ignored

## Keepalive Timer

`KeepAliveClient` tracks each initialized line in tunnel state and starts one periodic timer per worker during
`onStart()`.

Every `ping-interval` milliseconds, the worker-local timer walks the tracked lines for that worker and sends one empty
`ping` frame on each still-alive line.

Default interval:

- `60000 ms`

## Finish Behavior

On either directional `Finish`, `KeepAliveClient`:

1. removes the line from its tracked-line list
2. destroys its own per-line state
3. propagates the received directional finish

This matches Waterwall’s normal directional finish pattern and avoids touching line state after destruction.

## Configuration Example

```json
{
  "name": "keepalive-client",
  "type": "KeepAliveClient",
  "settings": {
    "ping-interval": 60000
  },
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

`KeepAliveClient` advertises `kNodeFlagSupportsSplice`. Framing continues for the
whole connection. Upstream encoding writes only the five-byte header into real
left padding; downstream decoding uses a five-byte `splice_stream_t` header
cache. Payload bodies remain eligible for private-pipe forwarding. Payloads
larger than 6 MiB are split using representation-aware range operations.
Pipe allocation or capacity pressure may select complete ordinary fallback.
Ping and pong frames use ordinary buffers.

Nested encoder input stays behind the active payload under a shared 8 MiB
logical-byte and 1,024-buffer reentry bound, counting the active suffix. The decoder serializes nested input,
limits nested retained bytes to 8 MiB, and limits retained allocation charge to
16 MiB, attempting beneficial ordinary compaction before refusing excess charge.
Complete frames in an admitted delivery drain before checking the 6 MiB + 5 byte
incomplete-remainder limit. Pause is forwarded promptly and does not interrupt
that synchronous batch. Timer-generated pings stop while upstream output is
paused and resume on a later timer tick after Resume.

Zero or oversized frame body lengths, admission failure and retained-storage overflow
close the borrowed line through its owner. Finish releases incomplete frames,
active encoder suffixes and queued reentrant input; this node never destroys
`line_t` itself.
