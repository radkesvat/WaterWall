<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/KeepAliveServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/KeepAliveServer.mdx, and all files must keep the same documentation version.
-->

# KeepAliveServer Node

`KeepAliveServer` is the peer tunnel for `KeepAliveClient`. It removes the same `3`-byte keepalive framing from
upstream traffic, forwards normal payload, and answers ping frames with pong frames.

The purpose of this tunnel is to periodically send/recv ping-pong messages that keep the connection appearing active, preventing timeout-based middleboxes (such as NAT devices and others) from closing it.

## Frame Format

Each frame starts with:

- `2` bytes: big-endian frame body length
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
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `3` bytes |
