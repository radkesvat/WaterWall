<!--
Documentation version: 152
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/Bgp4Server.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/Bgp4Server.mdx, and all files must keep the same documentation version.
-->

# Bgp4Server

`Bgp4Server` is the peer for `Bgp4Client`. It unwraps upstream BGP-like frames and wraps downstream stream payloads in the reverse direction.

The first upstream frame must be a synthetic BGP OPEN message. The server validates the marker, reads the frame length from a `buffer_stream_t`, checks that the first BGP type is OPEN, strips the OPEN fields and optional parameters, then forwards the remaining application payload upstream. Later upstream frames only strip the marker, length, and type.

Downstream payloads are wrapped as:

```text
16-byte marker | 2-byte body length | 1-byte BGP type | body
```

The length is network byte order and covers the type byte plus body bytes. `settings.password` is accepted for compatibility with the old configuration shape, but it remains unused by the protocol logic.

Protocol errors destroy local line state and close both directions in the usual middle-tunnel order: upstream finish first, downstream finish second. Normal directional finishes only forward the received finish direction after local cleanup. `Bgp4Server` is a layer-4 stream tunnel and does not create, destroy, or repurpose packet lines.

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
| `required_padding_left` | `19` bytes |
