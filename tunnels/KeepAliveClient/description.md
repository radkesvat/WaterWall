<!--
Documentation version: 154
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
- downstream empty `pong` frames acknowledge an outstanding ping in sensitive mode; otherwise they are ignored

## Keepalive Timer

`KeepAliveClient` creates a worker-local idle table when the first connection on
that worker reaches transport `Est`. Each established line has a recurring ping
item and, in sensitive mode, a separate item while waiting for a pong.

In both modes, the first ping is due one `ping-interval` after downstream transport
`Est`. The worker timer sends it on the first eligible check at or after that
deadline. Outgoing Pause leaves one probe due without allocating or sending it;
there is no burst of missed probes after Resume. Application traffic can flow
during the initial wait. In sensitive mode, the reply deadline starts immediately
before the ping is handed to the next node, never while it waits locally.

With sensitive mode disabled, the ping item sends one empty `ping` frame when due
and unpaused, then schedules its next interval. A blocked probe stays due and
retries after one second. There is no catch-up burst.

Default interval:

- `30000 ms`

## Optional Reply Watchdog

`sensitive-mode` defaults to `false`. When enabled, only one ping is outstanding
per line. An empty pong on that same line acknowledges it; application frames,
peer pings, unknown kinds and nonempty pongs do not.

`tolerance-ms` defaults to `90000` and must be an integer in `1..2147483647`.
A missing or late pong closes the borrowed connection through its owner. This
node does not recreate it. Deadlines use the owner event loop's monotonic clock.
The separate deadline item is canceled by a timely pong and is never extended by
the ping item. Expiry is handled on the first idle-table check at or after the
deadline, or when a late pong is decoded. New short deadlines may be checked about
one second late; this node does not guarantee subsecond wakeup precision.

Pause in either direction leaves the timer and any outstanding reply deadline
running. Downstream Pause delays Ping/Pong output toward `next`; Resume permits
pending replies and later timer checks to send. The watchdog closes an expired
line without waiting for Resume. An already-admitted pong can still acknowledge
a timely ping during Pause. Upstream Pause controls the opposite output direction.
At most 1,024 Pong replies may wait locally; excess peer pings close through the
normal owner. Resume stops draining if reentrant Pause or Finish occurs. Finish
discards pending replies and any outstanding ping wait.

The tolerance includes paused time, queueing and transfer time. Pongs share the same
ordered stream as normal frames and may wait behind a 6 MiB body, so choose a
tolerance that allows for the path's throughput and latency.

## Finish Behavior

On either directional `Finish`, `KeepAliveClient`:

1. cancels its ping and reply-deadline items and releases its worker tracking
2. destroys its own per-line state
3. propagates the received directional finish

This matches Waterwall’s normal directional finish pattern and avoids touching line state after destruction.

## Configuration Example

```json
{
  "name": "keepalive-client",
  "type": "KeepAliveClient",
  "settings": {
    "ping-interval": 30000,
    "sensitive-mode": false,
    "tolerance-ms": 90000
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
that synchronous batch. Timer checks continue during Pause, but new pings and
pending replies obey the outgoing Pause gate. Pause and Resume never postpone
an outstanding reply deadline.

Zero or oversized frame body lengths, admission failure and retained-storage overflow
close the borrowed line through its owner. Finish releases incomplete frames,
active encoder suffixes and queued reentrant input; this node never destroys
`line_t` itself.
