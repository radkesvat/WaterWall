<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/header-server.mdx, and both files must keep the same documentation version.
-->

# HeaderServer

`HeaderServer` consumes the one-time 2-byte port header produced by `HeaderClient` and applies it to `line->routing_context.dest_ctx.port` before initializing the next upstream tunnel.

When `settings.override` is `"dest_context->port"`, upstream `Init` is intentionally delayed until enough upstream payload has arrived to read the header. Payload bytes are staged in a `buffer_stream_t`, so the header may arrive split across reads. After the port is decoded, the server sends `tunnelNextUpStreamInit()` and forwards any remaining buffered payload upstream.

A numeric `settings.override` sets a constant destination port during `UpStreamInit` and does not consume a header. Use that mode without a `HeaderClient` in front of it, otherwise the client header remains application payload.

The port header is encoded in network byte order. Ports below 10 are rejected to preserve the old tunnel's conservative close behavior. Protocol errors close both directions after destroying local line state. Normal directional finishes destroy local state before forwarding the finish. `Pause`, `Resume`, and downstream `Est` are only reflected after the delayed upstream initialization has completed.

`HeaderServer` is a normal layer-4 stream tunnel. It does not create or destroy lines and must not be used as a packet-line lifecycle boundary.
