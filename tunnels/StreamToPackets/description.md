<!--
Documentation version: 152
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/StreamToPackets.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/StreamToPackets.mdx, and all files must keep the same documentation version.
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
- Extracts packet payload and dispatches it to the worker that owns the inner flow.
- Tracks one active source IP globally; several validated stream lines from that IP may be used together.
- On return path, validates the packet is a self-consistent IPv4 packet and sends it raw back to one active stream
  line chosen per inner flow (IPv6 is dropped).
- Excludes a paused stream line from selection and remaps its flows to the rest of the pool; packet output is
  dropped only when no active, unpaused line is available.

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

### One active source, many lines

Ownership is global to the tunnel instance, not per worker.

When a data line is initialized from the previous side, `StreamToPackets` creates a read stream parser for it and
registers it as a **candidate**. A candidate is tracked but not selectable: it carries no return traffic until it
produces its first valid IPv4 packet, or a valid sensitive-mode heartbeat.

The source identity is the concrete source IP from the line's source address context. The port is deliberately not
part of it: `TcpListener` stores the local listener port there, and reconnects use fresh ephemeral ports. Lines with
no concrete source IP - a directly composed in-process `PacketsToStream -> StreamToPackets` pair, for example -
share one explicit anonymous identity, so such compositions keep working, at the cost of not being able to tell two
anonymous peers apart.

Once a candidate is validated:

- if there is no active source, it becomes the active source and opens a new source generation
- if its source matches the active source, it simply joins that generation; every validated line from that IP stays
  usable at the same time
- if its source differs, it takes ownership: a new generation is published, and every line of the previous source,
  including idle candidates, is closed on its own worker through the previous side

Malformed bytes, buffer overflow and failed validation are never protocol proof, so they can neither activate a
candidate nor trigger a takeover. A line evicted by a takeover can never reclaim ownership, but a genuinely new
connection from the old IP can take over again once it produces valid traffic. This is **validated newest source
wins**: expose the listener only behind authentication or allowlisting on untrusted networks.

When the last active line of a generation finishes, the active source is cleared and return traffic is dropped until
a new line is validated.

Once the node manager begins stopping this instance, no line may be registered and no candidate may be promoted;
lines that are already active keep draining. A shutdown therefore never opens a new ownership epoch or queues
eviction work onto workers that are already going away.

An evicted line is closed by a task posted to its own worker. If that post fails for a reason other than shutdown -
an exhausted message pool, a loop that refuses a wakeup - and the takeover happens to be running on that line's own
worker, it is closed there instead. If it is not, there is no second channel to that worker and no way to close the
line, so the node fails closed: it requests an orderly program shutdown, falling back to an immediate abort if
worker 0 will not take the handoff. An old-source connection is never left running.

### Inner-flow worker affinity

The worker that owns an outer connection is chosen by the socket manager and is unrelated to the worker that owns an
inner IP flow. `StreamToPackets` therefore re-derives affinity from each decoded packet: it computes the shared
symmetric flow hash and dispatches the packet to `packet_line[hash % workers]`, forwarding directly when that is the
current worker and queueing to the target worker otherwise. Both directions of one flow reach the same packet
worker.

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
- the packet must be a self-consistent IPv4 packet (IPv6/malformed is dropped)
- the same symmetric flow hash selects one carrier from the active, unpaused lines of the current generation by
  rendezvous hashing, so one flow stays on one line while that pool is unchanged and different flows spread across
  the pool
- the packet is written raw to that line, on that line's own worker

Adding, pausing, resuming or removing a line changes the eligible pool and can move some flows to a different
carrier, so a small amount of reordering is possible around those transitions: a packet sent on the new carrier can
overtake one still in flight on the old one. This is a packet path, and the inner protocol is responsible for
ordering, exactly as it is over any network. A peer that requires strictly ordered delivery of the packets it gets
back must not depend on this node while stream lines are joining or leaving. Steady-state per-packet round-robin is
never used.

### Pause and resume behavior

Pause is per stream line, not global:

- a paused line is excluded from new flow selection, and its flows move to the remaining active lines
- when every active line is paused, return packets are dropped rather than queued into an unbounded global buffer
- resume makes the line selectable again, which restores its previous rendezvous winners

### Finish behavior

When an upstream data line finishes:

- it is removed from the line registry
- its parser state is destroyed
- nothing is sent back toward the previous side, which is the sender of that `Finish`
- if it was the last active line of the current generation, the active source is cleared and queued return writes
  from that generation become stale

Incoming stream lines are borrowed: `StreamToPackets` never destroys one, and it never finishes or destroys a worker
packet line.

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
- Ownership is one active source IP for the whole node, not one last line per worker. Put authentication or
  allowlisting in front of it on untrusted listeners.
- Return traffic can arrive on any line of the active source's pool, so the peer must be able to accept a decoded
  packet on any of its lines. `PacketsToStream` does exactly that.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` &#124; `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer3` |
| `required_padding_left` | `0` bytes |
