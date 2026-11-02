<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/Bgp4Server.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/Bgp4Server.mdx, and all files must keep the same documentation version.
-->

# Bgp4Server

`Bgp4Server` is the peer for `Bgp4Client`. It unwraps upstream BGP-like frames and wraps downstream stream payloads in the reverse direction.

The first upstream frame must be a synthetic BGP OPEN message. The server validates the marker, reads the frame length through the shared `splice_frame_reader_t` over a `splice_stream_t`, checks that the first BGP type is OPEN, strips the OPEN fields and optional parameters, then forwards the remaining application payload upstream. Later upstream frames only strip the marker, length, and type.

Downstream payloads are wrapped as:

```text
16-byte marker | 2-byte body length | 1-byte BGP type | body
```

The length is network byte order and covers the type byte plus body bytes. `settings.password` is accepted but ignored; it provides neither encryption nor authentication.

Protocol errors destroy local line state and close both directions in the usual middle-tunnel order: upstream finish first, downstream finish second. Normal directional finishes only forward the received finish direction after local cleanup. `Bgp4Server` is a layer-4 stream tunnel and does not create, destroy, or repurpose packet lines.

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
| `required_padding_left` | `19` bytes |

Both directions accept ordinary buffers, private-pipe splice buffers, and mixed
fragments. A fitting delivery is framed in place using reserved left padding
(39 bytes for the client, 19 for the server), including any existing resident
prefix. Larger outgoing deliveries are prepared as complete batches of separate
frame buffers before any callback; pipe creation or transfer pressure selects complete
ordinary best-fit fallback for the affected frame. There is no whole-delivery
ordinary aggregate.

The decoder caches the 19-byte marker/length/type header and forwards available
application body bytes incrementally. The server first gathers and validates the
ten fixed OPEN bytes, then consumes at most 255 optional bytes before releasing
application bytes. The remaining application's representation is preserved. The
client generates 3–10 optional bytes and subtracts the actual OPEN overhead from
its first frame's payload room. Empty deliveries emit nothing and do not consume
OPEN state. Exactly one OPEN is admitted per client line.

The shared fixed-header frame reader drains available body bytes from a top-level
receive batch before checking the incomplete remainder. That batch can exceed
**2,162,705 bytes** (`2 MiB + 65,553`). During a delivery callback, nested input
must fit that logical-byte limit together with older retained wire bytes,
including the cached header. It then joins the FIFO, and retained buffer charge
must fit **4,325,410 bytes** before nested admission returns. The same charge
limit applies to the incomplete remainder when the outer drain ends. Coalescing
or one beneficial compaction may release oversized backing storage before
refusal. Compaction may copy pipe-backed bytes into ordinary memory; the charge
limit bounds retained storage accounting, not process memory or transient peaks.
Incoming fragments have no entry-count cap. After available body bytes drain, the
incomplete remainder is smaller than 65,553 logical bytes.

Encoded output keeps its independent **2,162,705-byte limit**, including generated
headers, and **8 MiB retained-buffer charge limit**. These limits are independent of RAM profile,
pools, pipe capacity, platform and `misc.splice`. The maximum complete wire frame
is 65,553 bytes, and a non-OPEN frame carries at most 65,534 application bytes.

A decoded frame can produce several Payload callbacks; frame boundaries are not
application callback boundaries. If the connection ends during a frame, its
already delivered application prefix stays delivered. Both nodes borrow the
normal line and transform every payload, so neither can permanently bypass itself.
Pause and Resume use transparent default forwarding in both directions, including repeated
notifications. Available admitted bytes drain immediately without waiting for
Resume. A pump guard per direction preserves FIFO during reentrant callbacks;
the frame reader retains incomplete input, and the bounded output FIFO keeps
complete encoded batches ahead of reentrant input. The decoder validates any
complete FIFO-head header immediately after admission, including nested input;
only the outer drain delivers application bytes. Encoded batches pass their byte
and charge checks before their first callback.
Malformed data, retention-limit overflow or queue-capacity refusal closes only
the borrowed connection through its owner. Finish releases queued buffers and
pipes before forwarding away from the sender. These behaviors do not guarantee
zero-copy delivery or a throughput improvement.
