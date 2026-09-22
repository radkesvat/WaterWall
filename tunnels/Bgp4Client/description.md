<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/Bgp4Client.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/Bgp4Client.mdx, and all files must keep the same documentation version.
-->

# Bgp4Client

`Bgp4Client` wraps upstream stream payloads in BGP-like frames and unwraps downstream frames from `Bgp4Server`.

The intended pair is:

```text
TcpListener -> Bgp4Client -> ... -> Bgp4Server -> TcpConnector
```

On the first upstream payload, the client prepends a synthetic BGP OPEN body before the application bytes, then wraps the result with:

```text
16-byte marker | 2-byte body length | 1-byte BGP type | body
```

Later upstream payloads are wrapped with a random non-OPEN BGP type. Downstream payloads are parsed from a `splice_stream_t`, validated for marker and length, stripped of marker, length, and type, then forwarded toward the previous tunnel.

The body length is encoded in network byte order and covers the BGP type byte plus body bytes, matching the older tunnel's framing contract. `settings.password` is still accepted for configuration compatibility, but the historical implementation did not use it for encryption or authentication.

`Bgp4Client` initializes line state during `UpStreamInit`, forwards `Init` only after stream allocation succeeds, and destroys local line state before forwarding directional `Finish`. It advertises enough left padding for the largest first OPEN prefix. It is a normal layer-4 stream tunnel, not a packet-line tunnel.

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
| `required_padding_left` | `39` bytes |

Both directions accept ordinary buffers, private-pipe splice buffers, and mixed
fragments. A fitting delivery is framed in place using reserved left padding
(39 bytes for the client, 19 for the server), including any existing resident
prefix. Larger deliveries are prepared as complete batches of separate frame
buffers before any callback; pipe creation or transfer pressure selects complete
ordinary best-fit fallback for the affected frame. There is no whole-delivery
ordinary aggregate.

The decoder caches the 19-byte marker/length/type header and extracts one exact
body at a time. The server inspects only the ten fixed OPEN bytes and at most
255 optional bytes, preserving the remaining application's representation. The
client generates 3–10 optional bytes and subtracts the actual OPEN overhead from
its first frame's payload room. Empty deliveries emit nothing and do not consume
OPEN state. Exactly one OPEN is admitted per client line.

The fixed logical retention limit is **2,162,705 bytes per direction**
(`2 MiB + 65,553`), independent of RAM profile, pools, pipe capacity, platform and
`misc.splice`. Decoders count retained wire bytes, including the cached header;
encoders count queued encoded bytes including generated headers. Encoded output
also has a **1,024-frame FIFO cap**. Incoming fragments have no entry-count cap.
The maximum complete wire frame is 65,553 bytes, and a non-OPEN frame carries at
most 65,534 application bytes.

Each decoded frame produces its own callback. Downstream Pause controls upstream
output; upstream Pause controls downstream output. Drains stop immediately on
Pause and preserve FIFO order across reentrant input. Resume drains older work
before releasing the producer; an incomplete frame still permits producer Resume.
Malformed data, admission overflow or queue/stream allocation refusal closes only
the borrowed connection through its owner. Finish releases queued buffers and
pipes before forwarding away from the sender. Stream creation failure during Init
notifies only the initialized owner side. These behaviors do not guarantee
zero-copy delivery or a throughput improvement.
