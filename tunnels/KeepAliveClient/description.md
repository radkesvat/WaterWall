<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/KeepAliveClient.mdx, and both files must keep the same documentation version.
-->

# KeepAliveClient Node

`KeepAliveClient` is a small framing tunnel that wraps upstream payloads with a `3`-byte keepalive header and
periodically sends ping control frames on every live line it owns.

The purpose of this tunnel is to periodically send/recv ping-pong messages that keep the connection appearing active, preventing timeout-based middleboxes (such as NAT devices and others) from closing it.

This tunnel must reach KeepAliveServer for it to work.


It is designed to compose like other Waterwall middle tunnels. It does not invent a new line lifecycle and it does not
hold protocol state alive after a clean finish.

## Frame Format

Each transmitted frame starts with:

- `2` bytes: big-endian frame body length
- `1` byte: frame kind

Frame body length includes the `1`-byte frame kind plus any payload bytes.

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

## Packet-Line Rule

When the current line is the worker packet line, framing must not push a packet past `kMaxAllowedPacketLength`.

If `payload + 3` would exceed that limit:

- the tunnel logs an error
- the frame is dropped

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
