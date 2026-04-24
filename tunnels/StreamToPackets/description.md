# StreamToPackets Node

`StreamToPackets` is the inverse adapter of `PacketsToStream`.

It accepts a stream that contains framed packet bytes and reconstructs packet payload for the next packet-oriented node.

The current framing format is:

- 2-byte packet length prefix (`uint16`, network byte order)
- packet payload bytes

## What It Does

- Accepts a normal data line from the previous side.
- Buffers incoming stream bytes until a full framed packet is available.
- Extracts packet payload and forwards it to the next side.
- Tracks one active upstream data line per worker.
- On return path, prepends a 2-byte size field to packet payload and sends it back to the stream side.
- Drops packet output while the upstream data side is paused.

This tunnel is useful when transport is stream-oriented but packet boundaries must be preserved explicitly.

## Typical Placement

A common layout is:

- stream-oriented transport or processing nodes before `StreamToPackets`
- `StreamToPackets`
- packet-producing or packet-consuming nodes after it

### Basic two-server use case

- `server1`: `TunDevice` -> `PacketsToStream` -> `TcpConnector`
- `server2`: `TcpListener` -> `StreamToPackets` -> `TunDevice`

In this pattern, server2 rebuilds packets from the framed TCP stream created by server1.

## Configuration Example

```json
{
  "name": "stream-to-packet",
  "type": "StreamToPackets",
  "settings": {
    "sensitive-mode": true
  },
  "next": "packet-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"StreamToPackets"`.

- `next` `(string)`
  The next node that should receive reconstructed packet payload.

### `settings`

There are no required tunnel-specific settings in the current implementation.

## Optional `settings` Fields

- `sensitive-mode` `(boolean)`
  Enables sensitive-mode heartbeat handling for framed 5-byte control packets.

## Detailed Behavior

### Active data line per worker

When a data line is initialized from the previous side, `StreamToPackets` stores that line as the active line for the worker and creates a read stream parser.

If another upstream line replaces it on the same worker, parser state is reset so partial frame bytes do not leak across lines.

### Data flow direction

- Data side to packet side: previous node -> `StreamToPackets` -> reconstructed packets -> next node
- Packet side back to data side: next node -> `StreamToPackets` -> framed bytes -> previous data line

From the previous side, this tunnel behaves like a normal stream line.

From the next side, it behaves like a packet-producing/consuming boundary adapter.

### Frame extraction

Incoming upstream data is buffered until a complete frame is available.

The tunnel then:

- checks for at least 2 bytes
- reads packet length from the 2-byte prefix
- waits until `2 + length` bytes are available
- extracts payload and forwards it as one packet

Packet boundary detection is based on this explicit length prefix.

### Return path framing

When packet payload arrives back from the next side:

- optional IPv4 checksum recalculation is applied if requested by line state
- a 2-byte length prefix is prepended
- framed bytes are written to the active upstream data line

### Pause and resume behavior

When the upstream data line is paused:

- packet-side output back toward the stream side is dropped

When resumed:

- normal forwarding continues

### Finish behavior

When the active upstream data line finishes:

- active line reference is cleared
- parser buffer is reset

### Sensitive mode heartbeat

When `sensitive-mode` is enabled:

- if `StreamToPackets` reconstructs a framed 5-byte payload where every byte is `0xFF`, it treats that frame as a heartbeat ping instead of a real packet
- it replies downstream on the same stream line with a framed 5-byte payload of `0xDD`
- neither the ping nor the pong is forwarded to the packet side

### Buffering limits

The frame parser uses a fixed-size read stream.

Current limit:

- `65536 * 2` bytes

If buffered data exceeds that size, the read stream is emptied.

## Notes And Caveats

- This node expects framed bytes in `2-byte length + payload` format.
- It should usually be paired with `PacketsToStream` on the opposite side.
- Upstream `est` plus downstream `init`, `fin`, `pause`, and `resume` are not part of the intended normal callback path for this tunnel.
