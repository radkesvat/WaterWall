<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/PacketsToStream.mdx, and both files must keep the same documentation version.
-->

# PacketsToStream Node

`PacketsToStream` adapts a packet-oriented side of the chain to a stream-oriented side.

The current implementation is **IPv4-only**. It does not add any framing header: each outgoing IPv4 packet
is written to the stream as-is, and the on-wire format is a raw concatenation of IPv4 packets. Packet
boundaries are recovered from each packet's **IPv4 total-length field**, so no length prefix is needed.

Non-IPv4 payloads (including IPv6) are dropped in both directions.

## What It Does

- Accepts packet payload from the previous side.
- Creates and maintains one stream-facing line per worker toward the next node.
- For each outgoing packet, validates it is a self-consistent IPv4 packet and forwards it raw (IPv6 is dropped).
- Buffers return stream data and extracts complete IPv4 packets using the IPv4 total-length field.
- Sends each reconstructed packet back to the previous side.
- Recreates the stream-facing line if that line is closed.

This tunnel is a packet-to-stream adapter based on IPv4 header parsing, not explicit length framing.

## Typical Placement

A common layout is:

- a packet-producing or packet-consuming node before `PacketsToStream`
- `PacketsToStream`
- stream-oriented transport or processing nodes after it

### Basic two-server use case

- `server1`: `TunDevice` -> `PacketsToStream` -> `TcpConnector`
- `server2`: `TcpListener` -> `StreamToPackets` -> `TunDevice`

This works because `PacketsToStream` and `StreamToPackets` use the same IPv4-header-based, headerless format.

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

- `"none"`: default. No *configurable* validation is performed, but the size-based extractor still applies
  unconditional, lighter-than-`loose` structural checks before treating bytes as a packet: the head must be IPv4
  (version `4`), the IPv4 header length must be at least the minimum, and the IPv4 total length must be
  self-consistent (`>= header length`) and within the pipeline packet bound. These checks only decide how many
  bytes a packet consumes; they never reject a packet that passes them, so garbage that happens to look like a
  valid IPv4 header is still forwarded (see Garbage Resilience).
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

`IpManipulator` tricks such as `carry-original-tcp-flags` and source/destination port ghosting append bytes by increasing the IPv4
total-length field. Chained tricks are therefore valid as long as each transformed packet's IPv4 total length matches the
actual packet length on the wire and any requested checksum recalculation has happened before validation.

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

### Wire format

There is no framing header. Each packet is written to the stream as a raw IPv4 packet:

- N bytes: the IPv4 packet, whose own total-length field is `N`

Maximum packet size accepted by this node is limited by `kMaxAllowedPacketLength`.

### Checksum recalc behavior

Before sending packet payload to the stream side:

- if `line->recalculate_checksum` is enabled and payload is IPv4,
- full packet checksum is recalculated,
- then the packet is forwarded raw if it is a self-consistent IPv4 packet (IPv6/malformed is dropped).

### Packet decoding on return path

Return traffic from the next side is buffered in a read stream.

The tunnel then:

- waits for at least a full minimum IPv4 header
- reads the IPv4 total-length field
- waits until the whole packet (`total length`) is available
- emits one packet back to the previous side

Packet boundary recovery is based on the IPv4 total-length field.

### Garbage Resilience

The decoder never trusts the stream. The worst a hostile or corrupted stream can do is make the decoder read
mis-sized "packets" and forward garbage until the byte stream happens to realign on a real IPv4 header; from that
point correct packets are read again. No input pattern can crash the node, read out of bounds, or stall it:

- a head that is not a structurally-valid IPv4 header causes the decoder to resynchronize, discarding bytes until
  the next plausible IPv4 start
- a head that looks like a valid IPv4 header is trusted for its declared size only
- forward progress of at least one byte is guaranteed on every step

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

- every `interval-ms`, `PacketsToStream` sends a heartbeat upstream on the current stream-facing line. Because the
  wire format is a raw concatenation of IPv4 packets, the heartbeat is itself a small, fully valid IPv4 packet
  tagged with a reserved experimentation protocol number and a `0xFF` payload
- it does not send another heartbeat while the previous one is still waiting for a reply
- if the matching `0xDD`-payload heartbeat reply comes back on that same active line, the heartbeat is considered successful and is not emitted to the packet side
- if no reply arrives within `tolerance-ms`, the current stream-facing line is finished locally, discarded, and recreated using the same worker-local bridge state

This heartbeat lives entirely on the stream side and does not close the shared worker packet line.

### Buffering limits

The read stream uses a fixed overflow limit.

Current limit:

- `65536 * 2` bytes

If buffered return data grows beyond that limit, the read stream is emptied.

## Notes And Caveats

- This node is IPv4-length based (no framing header), not `2-byte length + payload` based.
- It is IPv4-only; IPv6 and non-IPv4 payloads are dropped in both directions.
- Pair it with `StreamToPackets` on the other side to restore packet boundaries.
- Upstream `est`, `pause`, `resume`, and `finish`, plus downstream `init`, are not part of the intended normal callback path for this tunnel.
