# PacketsToStream Node

`PacketsToStream` adapts a packet-oriented side of the chain to a stream-oriented side.

The current implementation frames each packet by adding a **2-byte length prefix** (network byte order / big-endian), then sends that framed data over a normal stream line.

On the reverse path, it reads the same 2-byte length prefix and reconstructs packet boundaries.

## What It Does

- Accepts packet payload from the previous side.
- Creates and maintains one stream-facing line per worker toward the next node.
- For each outgoing packet, prepends a 2-byte packet size field.
- Buffers return stream data and extracts complete framed packets.
- Sends each reconstructed packet back to the previous side.
- Recreates the stream-facing line if that line is closed.

This tunnel is a packet-to-stream adapter based on explicit length framing, not IPv4 header parsing.

## Typical Placement

A common layout is:

- a packet-producing or packet-consuming node before `PacketsToStream`
- `PacketsToStream`
- stream-oriented transport or processing nodes after it

### Basic two-server use case

- `server1`: `TunDevice` -> `PacketsToStream` -> `TcpConnector`
- `server2`: `TcpListener` -> `StreamToPackets` -> `TunDevice`

This works because `PacketsToStream` and `StreamToPackets` use the same 2-byte framing format.

## Configuration Example

```json
{
  "name": "packet-to-stream",
  "type": "PacketsToStream",
  "settings": {
    "sensitive-mode": true,
    "interval-ms": 50,
    "tolerance-ms": 150
  },
  "next": "stream-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"PacketsToStream"`.

- `next` `(string)`
  The next node that should receive the forwarded data payload.

### `settings`

There are no required tunnel-specific settings in the current implementation.

## Optional `settings` Fields

- `sensitive-mode` `(boolean)`
  Enables sensitive-mode heartbeat handling for the worker-local stream line.

- `interval-ms` `(integer, default: 50)`
  Client-side only. Heartbeat send interval in milliseconds when `sensitive-mode` is enabled.

- `tolerance-ms` `(integer, default: 150)`
  Client-side only. Maximum time to wait for a heartbeat reply before the current stream line is closed and recreated.

- `packet-validation-level` `(string, default: "none")`
  Optional packet validation mode. See the Packet Validation section for usage and caveats.

## Packet Validation

`packet-validation-level` controls validation of packets decoded from incoming downstream framed data. Upstream packets
that `PacketsToStream` receives from the packet side are not validated before framing.

Supported values:

- `"none"`: default. No packet validation is performed.
- `"loose"`: drops non-IPv4 packets and malformed IPv4 packets. Checks include minimum IPv4 header size, version,
  IPv4 header length, and IPv4 total length matching the received frame payload length.
- `"hard"`: applies `loose` checks, verifies the IPv4 header checksum, and verifies TCP, UDP, and ICMP checksums for
  non-fragmented packets. IPv4 UDP packets with checksum `0` are accepted because that is valid for IPv4 UDP.

Example:

```json
"settings": {
  "packet-validation-level": "hard"
}
```

When validation drops a decoded downstream packet, `PacketsToStream` writes a warning log with the validation level and
reason.

`IpManipulator` tricks such as `bit-transport` and source/destination port ghosting append bytes by increasing the IPv4
total-length field. Chained tricks are therefore valid as long as each transformed packet's IPv4 total length matches the
framed packet length and any requested checksum recalculation has happened before validation.

For fragmented IPv4 packets in `"hard"` mode, the IPv4 header checksum is verified. TCP/UDP/ICMP checksums are skipped
for fragments because transport checksums can only be fully verified after reassembly.


## Detailed Behavior

### Worker-local data line

`PacketsToStream` maintains a stream-facing line for each worker as needed.

When traffic is initialized on that worker:

- the tunnel creates a new line toward the next node
- stores it in worker-local state
- initializes the next node with that new line

That data line is then reused for packet payload arriving on the same worker.

### Data flow direction

- Packet side to data side: previous node -> `PacketsToStream` -> stream-facing line -> next node
- Data side back to packet side: next node -> `PacketsToStream` -> reconstructed packet -> previous node

From the packet side, this tunnel behaves like a packet-preserving adapter.

From the next side, it behaves like a normal line carrying framed bytes.

### Framing format

Each packet is encoded as:

- 2 bytes: packet length (`uint16`, network byte order)
- N bytes: raw packet payload

Maximum packet size accepted by this node is limited by `kMaxAllowedPacketLength`.

### Checksum recalc behavior

Before sending packet payload to the stream side:

- if `line->recalculate_checksum` is enabled and payload is IPv4,
- full packet checksum is recalculated,
- then normal framing is applied.

### Frame decoding on return path

Return traffic from the next side is buffered in a read stream.

The tunnel then:

- waits for at least 2 bytes
- reads framed packet length
- waits until the whole frame (`2 + length`) is available
- emits one packet back to the previous side

Packet boundary recovery is based on this 2-byte prefix.

### Pause and resume behavior

When the downstream side pauses the stream-facing line, `PacketsToStream` marks the packet-facing side paused and
propagates pause back to the previous packet-side node.

While paused, if the previous node ignores backpressure:

- incoming packet payload is dropped instead of buffered

When resume arrives:

- resume is propagated back to the previous packet-side node
- packet forwarding continues normally

### Finish and line recreation

If the stream-facing line toward the next node finishes:

- the old line is discarded
- the read buffer is cleared
- a fresh stream-facing line is created
- the next node is initialized again on that new line

This keeps the packet-facing role stable while allowing automatic recreation of the stream-side line.

### Sensitive mode heartbeat

When `sensitive-mode` is enabled:

- every `interval-ms`, `PacketsToStream` sends a framed 5-byte `0xFF` heartbeat upstream on the current stream-facing line
- it does not send another heartbeat while the previous one is still waiting for a reply
- if a framed 5-byte `0xDD` reply comes back on that same active line, the heartbeat is considered successful and is not emitted to the packet side
- if no reply arrives within `tolerance-ms`, the current stream-facing line is finished locally, discarded, and recreated using the same worker-local bridge state

This heartbeat lives entirely on the stream side and does not close the shared worker packet line.

### Buffering limits

The read stream uses a fixed overflow limit.

Current limit:

- `65536 * 2` bytes

If buffered return data grows beyond that limit, the read stream is emptied.

## Notes And Caveats

- This node is framing-based (`2-byte length + payload`), not IPv4-length based.
- Pair it with `StreamToPackets` on the other side to restore packet boundaries.
- Upstream `est`, `pause`, `resume`, and `finish`, plus downstream `init`, are not part of the intended normal callback path for this tunnel.
