<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/header-client.mdx, and both files must keep the same documentation version.
-->

# HeaderClient

`HeaderClient` prepends a one-time 2-byte port header to the first upstream payload on each normal layer-4 line.

The usual pair is:

```text
TcpListener -> HeaderClient -> ... -> HeaderServer -> TcpConnector
```

With `settings.data` set to `"src_context->port"`, the client writes the accepted connection's source port into the first payload. A numeric `settings.data` value writes that constant port instead. The port is encoded in network byte order.

The tunnel initializes per-line state in `UpStreamInit`, forwards `Init` immediately to the next tunnel, and only mutates the first upstream payload. Downstream payload, `Est`, `Pause`, and `Resume` are passed back unchanged. Finish callbacks destroy the tunnel line state before forwarding the directional finish.

`HeaderClient` requires 2 bytes of left padding because it prepends the header with `sbufShiftLeft()`. It is a layer-4 tunnel and should not be used as packet-line shared state.
