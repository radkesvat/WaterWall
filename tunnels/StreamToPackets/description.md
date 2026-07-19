<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/StreamToPackets.mdx, and both files must keep the same documentation version.
-->

# StreamToPackets Node

`StreamToPackets` is the inverse adapter of `PacketsToStream`.

It accepts a stream that contains a raw concatenation of IPv4 packets and reconstructs packet payload for the next
packet-oriented node.

The current format is **IPv4-only** and has no framing header:

- the stream is a back-to-back sequence of IPv4 packets
- packet boundaries are recovered from each packet's IPv4 total-length field

Non-IPv4 payloads (including IPv6) are dropped in both directions.

## What It Does

- Accepts a normal data line from the previous side.
- Buffers incoming stream bytes until a full IPv4 packet is available.
- Extracts packet payload and forwards it to the next side.
- Tracks one active upstream data line per worker.
- On return path, validates the packet is a self-consistent IPv4 packet and sends it raw back to the stream side (IPv6 is dropped).
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
  Enables sensitive-mode heartbeat handling using small tagged IPv4 heartbeat packets.

- `packet-validation-level` `(string, default: "none")`
  Optional packet validation mode. See the Packet Validation section for usage and caveats.

## Packet Validation

`packet-validation-level` controls validation of packets decoded from incoming upstream framed data. Downstream packets
that `StreamToPackets` receives from the packet side are not validated before framing.

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

When validation drops a decoded upstream packet, `StreamToPackets` writes a warning log with the validation level and
reason.

`IpManipulator` tricks such as `preserve-tcp-bitflags` and source/destination port ghosting append bytes by increasing the IPv4
total-length field. Chained tricks are therefore valid as long as each transformed packet's IPv4 total length matches the
actual packet length on the wire and any requested checksum recalculation has happened before validation.

For fragmented IPv4 packets in `"hard"` mode, the IPv4 header checksum is verified. TCP/UDP/ICMP checksums are skipped
for fragments because transport checksums can only be fully verified after reassembly.


## Detailed Behavior

### Active data line per worker

When a data line is initialized from the previous side, `StreamToPackets` stores that line as the active line for the worker and creates a read stream parser.

If another upstream line replaces it on the same worker, parser state is reset so partial frame bytes do not leak across lines.

### Data flow direction

- Data side to packet side: previous node -> `StreamToPackets` -> reconstructed packets -> next node
- Packet side back to data side: next node -> `StreamToPackets` -> raw IPv4 packets -> previous data line

From the previous side, this tunnel behaves like a normal stream line.

From the next side, it behaves like a packet-producing/consuming boundary adapter.

### Packet extraction

Incoming upstream data is buffered until a complete IPv4 packet is available.

The tunnel then:

- checks for at least a full minimum IPv4 header
- reads the IPv4 total-length field
- waits until `total length` bytes are available
- extracts the packet and forwards it as one packet

Packet boundary detection is based on the IPv4 total-length field.

### Garbage Resilience

The extractor never trusts the stream. The worst a hostile or corrupted stream can do is make it read mis-sized
"packets" and forward garbage until the byte stream happens to realign on a real IPv4 header; from that point
correct packets are read again. No input pattern can crash the node, read out of bounds, or stall it: a head that
is not a structurally-valid IPv4 header triggers resynchronization (discarding bytes until the next plausible IPv4
start), a head that looks valid is trusted only for its declared size, and at least one byte of forward progress is
guaranteed on every step.

### Return path

When packet payload arrives back from the next side:

- optional IPv4 checksum recalculation is applied if requested by line state
- the packet is written raw to the active upstream data line if it is a self-consistent IPv4 packet (IPv6/malformed is dropped)

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

- if `StreamToPackets` reconstructs a heartbeat packet (a small IPv4 packet tagged with the reserved experimentation
  protocol number and an all-`0xFF` payload), it treats it as a heartbeat ping instead of a real packet
- it replies downstream on the same stream line with the matching heartbeat packet carrying an all-`0xDD` payload
- neither the ping nor the pong is forwarded to the packet side

### Buffering limits

The frame parser uses a fixed-size read stream.

Current limit:

- `65536 * 2` bytes

If buffered data exceeds that size, the read stream is emptied.

## Notes And Caveats

- This node expects a raw concatenation of IPv4 packets (no framing header); boundaries come from the IPv4 total-length field.
- It is IPv4-only; IPv6 and non-IPv4 payloads are dropped in both directions.
- It should usually be paired with `PacketsToStream` on the opposite side.
- Upstream `est` plus downstream `init`, `fin`, `pause`, and `resume` are not part of the intended normal callback path for this tunnel.
