<!--
Documentation version: 123
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/IpManipulator.mdx, and both files must keep the same documentation version.
-->

# IpManipulator Node

`IpManipulator` is a packet tunnel that mutates IPv4 packets in place.

It is meant for layer-3 chains where the payload is already a raw IP packet, not a normal TCP stream line.

The current implementation provides these classes of tricks:

- protocol-number swapping
- TLS ClientHello copy (`first-sni`)
- TLS ClientHello multi-segment split-route delay (`smuggle-sni`)
- TLS ClientHello overlap split (`overlap-sni`)
- TLS ClientHello SYN/FIN overlap (`synfin-sni`)
- TLS ClientHello ECH-aware transport split (`ech-sni-trick`)
- mirrored TCP FIN injection (`smuggle-fin`)
- TLS ClientHello fragmentation and shuffle (`sni-blender`)
- TCP flag bit rewriting
- source and destination port ghost tailing with transport-port remapping
- final-packet duplication

## What It Does

- Reads raw packet payload on the upstream and downstream packet paths.
- Applies enabled packet tricks in place.
- Can inject a crafted mirrored FIN/ACK packet on a dedicated upstream helper branch.
- Can hold the third upstream packet only when it begins an incomplete TLS ClientHello, overlap it with a crafted fake ClientHello after the contiguous completing packet arrives, send a crafted server-side TLS packet on a helper upstream branch, emit a fake TCP SYN on the same 4-tuple, and then flush the remaining real ClientHello bytes. If completion does not arrive within the overlap hold timeout, the held packet is released unchanged.
- Can hold the third upstream packet only when it begins an incomplete TLS ClientHello, complete it with the contiguous following packet, then emit an enlarged real first TLS chunk, a client-looking FIN packet, a fake TCP SYN, a full crafted fake ClientHello, one valid generated TLS-looking filler packet, and the remaining real TLS bytes immediately on the normal upstream path. If completion does not arrive within the synfin hold timeout, the held packet is released unchanged.
- Can capture an upstream TLS ClientHello across one or more TCP segments regardless of packet ordinal, locate a fake TLS ClientHello embedded inside the `encrypted_client_hello` payload, send that byte range first as an out-of-order TCP segment, and then release the original captured ClientHello packets after a delay without changing the TLS bytes.
- Optionally duplicates the final outgoing packet after all other enabled tricks.
- Updates IPv4 header and TCP checksums in place for protocol swaps and simple TCP flag changes; size-changing or payload-crafting tricks request full checksum recalculation.
- Can replace one outgoing TLS ClientHello packet with multiple shuffled IP fragments.

This is a packet tunnel created with `packettunnelCreate()`, so normal stream-style `Init` and `Finish` callbacks are not part of its intended usage.

## Typical Placement

`IpManipulator` belongs in raw-packet chains, for example between packet-oriented nodes such as:

- `TunDevice`
- `WireGuardDevice`
- `RawSocket`
- other layer-3 packet tunnels

Typical use cases include:

- changing protocol numbers to evade simple filtering
- sending a crafted TLS ClientHello copy before the real ClientHello
- sending a mirrored FIN/ACK packet on a helper upstream branch without consuming the original packet
- fragmenting a TLS ClientHello to alter packet shape
- testing how a path behaves when TCP control bits are rewritten

## Configuration Example

```json
{
  "name": "ip-manipulator",
  "type": "IpManipulator",
  "settings": {
    "protoswap-tcp": 253,
    "protoswap-udp": 252,
    "sni-blender": true,
    "sni-blender-packets": 4,
    "packet-duplicate": 2,
    "source-port-ghost": true,
    "dest-port-ghost": true
  },
  "next": "next-packet-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"IpManipulator"`.

### `settings`

At least one trick must be enabled.

If none of the supported trick settings are present, tunnel creation fails with:

- `IpManipulator: no tricks are enabled, nothing to do`

## Optional `settings` Fields

### Protocol-swap settings

- `protoswap` `(integer)`
  Alias for `protoswap-tcp`.

- `protoswap-tcp` `(integer)`
  Replacement IP protocol number for TCP packets.

- `protoswap-udp` `(integer)`
  Replacement IP protocol number for UDP packets.

Replacement values must not be the literal TCP (`6`) or UDP (`17`) protocol
numbers, even when only one family is configured, because genuine traffic using
the reused number could not be distinguished from mapped traffic. When both
families are enabled, their configured replacement values must also be distinct.

`protoswap-tcp-2` has been removed. Configurations that still contain it fail
at startup instead of silently changing behavior. Migrate to the single,
reversible `protoswap-tcp` mapping; all fragments of an IPv4 datagram then use
the same replacement number.

### SNI blender settings

- `sni-blender` `(boolean)`
  Enables the TLS ClientHello fragmentation trick.

- `sni-blender-packets` `(integer)`
  Required when `sni-blender` is enabled.

  Valid range in the current implementation:
  - `2` to `16`

### Packet duplication settings

- `packet-duplicate` `(integer)`
  Optional.

  Duplicates each final outgoing packet this many times, then sends the original packet once.

  This is applied as the last step of `IpManipulator`, after all other enabled tricks have finished shaping the packet.

### first-sni settings

- `first-sni` `(string)`
  Enables the `first-sni` trick and sets the SNI that will be written into the crafted TLS ClientHello copy.

- `first-sni-ttl` `(integer)`
  Optional.

  When present, the crafted `first-sni` packet is sent with this IPv4 TTL value.

- `first-sni-count` `(integer)`
  Optional.

  Number of crafted `first-sni` packets to send before the original ClientHello.

  Defaults to `1`.

- `first-sni-replay-delay` `(integer)`
  Optional.

  Delay in milliseconds between crafted `first-sni` replays after the first one.

  Defaults to `0`.

  This value only matters when `first-sni-count` is greater than `1`.

- `first-sni-final-delay` `(integer)`
  Optional.

  Delay in milliseconds between the last crafted `first-sni` packet and the original ClientHello.

  Defaults to `0`.

- `first-sni-random-tcp-sequence` `(boolean)`
  Optional.

  When `true`, the crafted `first-sni` packet gets a fresh random TCP sequence number before it is sent.

  When `false` or omitted, the crafted `first-sni` packet keeps the original TCP sequence number.

### smuggle-sni settings

- `smuggle-sni` `(string)`
  Enables the `smuggle-sni` trick and sets the SNI that will be written into the delayed fake TLS ClientHello copy.

- `smuggle-sni-delay-ms` `(integer)`
  Optional.

  Delay in milliseconds between sending the real captured ClientHello to `real-sni-upstream-node` and sending the crafted `smuggle-sni` packet to the normal next tunnel.

  Defaults to `0`.

- `real-sni-upstream-node` `(string)`
  Required when `smuggle-sni` is enabled.

  Names another node in the same config that will receive the real captured ClientHello on the upstream path.

  In the current design this should be a dedicated branch head, not the same node as the normal `next`.

### overlap-sni settings

- `overlap-sni` `(string)`
  Enables the `overlap-sni` trick and sets the SNI that will be written into the crafted Chrome-like TLS ClientHello.

  In the current implementation, the first two upstream packets pass unchanged. The third packet is held only when its payload begins an incomplete TLS ClientHello record, and the contiguous fourth packet completes that record. Complete ClientHellos and non-TLS payloads pass immediately. If the completing segment does not arrive within `overlap-sni-hold-timeout-ms`, the held packet is released unchanged and the flow becomes passthrough. `IpManipulator` then generates its own Chrome-like TLS ClientHello, rejects the flow if the real SNI starts before the generated hello length, otherwise sends:
  - packet `Y` with the first generated-length bytes from the real captured ClientHello
  - one crafted server-side TLS packet through `crafted-server-hello-upstream-node`, built from the real downstream `SYN|ACK` header and a built-in server-hello payload
  - one fake zero-payload TCP `SYN` packet on the same 4-tuple
  - packet `X` with the generated fake ClientHello bytes on the same TCP sequence range, delayed through the overlap delay channel
  - the remaining real captured ClientHello bytes in additional delayed TCP packets

- `overlap-sni-delay-ms` `(integer)`
  Optional.

  Delay in milliseconds applied to overlap-sni packets that are sent after the fake TCP `SYN`, and to later upstream packets on the same flow while the overlap delay window remains active.

  Defaults to `0`.

  The overlap delay window duration itself is a code-level constant in the current implementation.

  Later packets use that flow's absolute window deadline and a bounded FIFO,
  rather than each receiving a fresh copy of the configured delay. The crafted
  overlap tail is scheduled before the FIFO can release.

- `overlap-sni-hold-timeout-ms` `(integer)`
  Optional.

  Maximum time in milliseconds to hold an incomplete first ClientHello segment while waiting for its contiguous completion. Expiry fails open by releasing the segment unchanged.

  Valid range: greater than `0`

  Defaults to `50`.

- `overlap-sni-syn-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the fake overlap-sni TCP `SYN` packet.

  Valid range: `0` to `255`

  When omitted, the fake TCP `SYN` keeps the original packet TTL.

- `crafted-server-hello-upstream-node` `(string)`
  Required when `overlap-sni` is enabled.

  Names another node in the same config that will receive the crafted server-side TLS packet on the upstream path.

  In the current design this should be a dedicated branch head, not the same node as the normal `next`.

### ech-sni-trick settings

- `ech-sni-trick` `(string)`
  Enables the `ech-sni-trick`.

  Must be between 1 and 255 bytes, the same TLS `host_name` boundary `TlsClient` enforces.

  In the current architecture, this value should match `TlsClient.settings.ech-sni-trick` for the same flow. `TlsClient` is responsible for embedding the fake ClientHello inside the GREASE `encrypted_client_hello` payload, and `IpManipulator` is responsible for the transport-level out-of-order send and delayed release. This remains GREASE camouflage rather than real encrypted ECH.

  Capture is sequence aware and does not depend on packet ordinals. A flow is opened by a payload-free TCP `SYN` (plain or with ECN `ECE`/`CWR`); TCP Fast Open SYN data is not supported and passes through. Capture then starts on the first upstream packet that carries a recognizable beginning of a TLS ClientHello record, and continues over contiguous following segments until the exact TLS record length is complete. Payload-free packets, including ACK-only packets before or between ClientHello segments, pass unchanged and never advance or disable capture.

  Capture is bounded by the shared TLS capture helper:
  - at most 16 captured packets
  - at most a 16384-byte TLS record
  - a 1500 ms capture timeout

  A sequence gap, an overlap the helper cannot prove is a retransmission, a malformed record, an unsupported layout, exceeding the packet or size limit, and the capture timeout all fail open: the held originals are released unchanged and in TCP sequence order, and that flow generation becomes passthrough. Once a generation is passthrough its later packets are not recaptured.

  When capture completes, `IpManipulator` requires:
  - a valid SNI extension
  - a valid `encrypted_client_hello` extension
  - exactly one embedded inner TLS ClientHello inside the ECH payload whose own SNI parses completely and equals the configured `ech-sni-trick` value byte for byte

  A candidate that is truncated, malformed, has no SNI, carries a different host name, or is only structurally TLS-looking is rejected, and more than one exactly matching candidate is ambiguous and also rejected. Every rejection fails open: the captured originals leave unchanged, in order, and no fake inner packet is emitted.

  When those checks pass, `IpManipulator` keeps the captured ClientHello bytes unchanged and sends:
  - one out-of-order TCP packet carrying only the fake inner ClientHello bytes from the ECH payload, using the TCP sequence number that corresponds to those bytes inside the original ClientHello stream
  - after `data-shard-1-delay`, original captured packet 1 unchanged
  - after an additional `data-shard-2-delay`, original captured packets 2 through N unchanged, emitted consecutively in their original sequence order

  A one-packet capture therefore uses only `data-shard-1-delay` and arms no second timer, a two-packet capture keeps the previous byte-for-byte and timing behaviour, and a three-or-more-packet capture never creates independently scheduled equal-deadline messages that could reorder.

  During the release window only an exact retransmission of a still-pending original segment is swallowed. ACK-only packets, non-overlapping later application data, and any partial or ambiguous overlap pass through unchanged. TCP `FIN` and `RST` packets are connection-lifecycle traffic and are never swallowed. During release, an upstream graceful `FIN` flushes every pending original ahead of itself, while an upstream `RST` discards pending originals. A downstream close cancels pending originals, and an upstream close during an incomplete capture releases the held originals before forwarding the close packet while a downstream close disposes of that incomplete capture without later injection.

  Each delayed original and each capture is bound to the nonzero generation of the ECH flow that captured it as well as its 4-tuple. Reusing the same 4-tuple starts a new generation and invalidates the previous generation's capture and pending originals first, so a timer or capture left from the previous connection cannot release stale ClientHello data.

  In the current implementation, the crafted out-of-order `ech-sni-trick` TCP packet is sent with the `PSH` flag set so it is less likely to be buffered by middle services.

  If the out-of-order fake-inner packet would exceed `GLOBAL_MTU_SIZE`, the flow is rejected instead of being reshaped.

- `data-shard-1-delay` `(integer)`
  Optional.

  Delay in milliseconds between sending the out-of-order fake inner ClientHello segment and releasing original captured packet 1.

  Defaults to `0`.

- `data-shard-2-delay` `(integer)`
  Optional.

  Additional delay in milliseconds between releasing original captured packet 1 and releasing original captured packets 2 through N. Those remaining originals are emitted consecutively in sequence order from that second release. After they are released, the original ClientHello has been fully sent. A one-packet capture ignores this setting.

  Defaults to `0`.

### synfin-sni settings

- `synfin-sni` `(string)`
  Enables the `synfin-sni` trick and sets the SNI that will be written into the crafted Chrome-like TLS ClientHello.

  In the current implementation, the first two upstream packets pass unchanged. The third packet is held only when its payload begins an incomplete TLS ClientHello record, and the contiguous fourth packet completes that record. Complete ClientHellos and non-TLS payloads pass immediately. If the completing segment does not arrive within `synfin-sni-hold-timeout-ms`, the held packet is released unchanged and the flow becomes passthrough. `IpManipulator` then generates its own Chrome-like TLS ClientHello, rejects the flow if the real SNI starts before the generated hello length, otherwise sends:
  - one real TLS data packet carrying the first `generated-length + extra-range` bytes from the captured real ClientHello on the original TCP sequence range
  - one zero-payload client-side close packet on the sequence number immediately after that first real chunk
  - one fake zero-payload TCP `SYN` packet on the same 4-tuple
  - one full crafted TLS data packet carrying the generated fake ClientHello on the original captured first-data TCP sequence range
  - one additional valid generated TLS-looking data packet whose payload length fills only that extra configured overlap range immediately after the crafted fake ClientHello on that same original sequence space
  - the remaining real captured ClientHello bytes in additional immediate TCP packets

  By default that close packet is `FIN|ACK`. When `synfin-sni-use-rst` is enabled, `IpManipulator` sends `RST|ACK` instead on the same post-fake-data sequence number.

  The fake `SYN` is rebuilt from the original captured `SYN` header template for that flow, so when checksum randomization is disabled it preserves the original SYN-style TCP header shape instead of cloning a later data packet. `IpManipulator` first sends the real first-data chunk so the destination server consumes the real beginning of the ClientHello, then emits the close packet and fake `SYN`, and only after that sends the generated fake ClientHello plus one valid generated TLS-looking filler packet on the original captured first-data sequence range. The configured extra overlap is chosen randomly per flow and is clamped so the real first-data chunk still stops before the real SNI hostname bytes.

  The complete crafted sequence is emitted immediately in that order. There is
  no artificial per-packet 20 ms sleep or configurable pacing delay.

- `synfin-sni-hold-timeout-ms` `(integer)`
  Optional.

  Maximum time in milliseconds to hold an incomplete first ClientHello segment while waiting for its contiguous completion. Expiry fails open by releasing the segment unchanged.

  Valid range: greater than `0`

  Defaults to `50`.

- `synfin-sni-additional-range-min` `(integer)`
  Optional.

  Minimum number of extra real ClientHello payload bytes to append to the first real `packet_y` chunk beyond the crafted fake ClientHello length.

  When present without `synfin-sni-additional-range-max`, this value is also used as the fixed extra overlap length.

  Valid range: `0` to `65535`

  Defaults to `0`.

- `synfin-sni-additional-range-max` `(integer)`
  Optional.

  Maximum number of extra real ClientHello payload bytes to append to the first real `packet_y` chunk beyond the crafted fake ClientHello length.

  `IpManipulator` chooses one random value per flow inside the configured range, then clamps it so the enlarged real first chunk still ends before the real SNI hostname bytes and before the captured ClientHello payload ends. That same chosen extra length is then filled on the original captured sequence range by one valid generated TLS-looking data packet sent immediately after `packet_x`.

  Valid range: `0` to `65535`

  Defaults to `0`.

- `synfin-sni-syn-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the crafted `SYN` packet.

  Valid range: `0` to `255`

  When omitted, the crafted `SYN` keeps the captured packet TTL.

- `synfin-sni-fin-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the crafted close packet (`FIN|ACK` by default, `RST|ACK` when `synfin-sni-use-rst` is enabled).

  Valid range: `0` to `255`

  When omitted, the crafted `FIN` keeps the captured packet TTL.

- `synfin-sni-fake-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the full crafted fake ClientHello packet that carries the generated `synfin-sni` payload bytes.

  This does not affect the enlarged real first TLS data packet, the generated TLS-looking filler packet after `packet_x`, or the remaining real captured ClientHello tails.

  Valid range: `0` to `255`

  When omitted, the full crafted fake ClientHello packet keeps the captured packet TTL.

- `synfin-sni-random-syn-checksum` `(boolean)`
  Optional.

  When `true`, the crafted `SYN` is sent with randomized IPv4 and TCP checksum fields instead of a recomputed valid checksum.

  Defaults to `false`.

- `synfin-sni-random-fin-checksum` `(boolean)`
  Optional.

  When `true`, the crafted close packet is sent with randomized IPv4 and TCP checksum fields instead of a recomputed valid checksum.

  Defaults to `false`.

- `synfin-sni-random-syn-sequence` `(boolean)`
  Optional.

  When `true`, the crafted `SYN` uses a fresh random TCP sequence number.

  When `false` or omitted, the crafted `SYN` uses the captured sequence pattern (`real_seq - 1`).

- `synfin-sni-random-fin-sequence` `(boolean)`
  Optional.

  When `true`, the crafted close packet uses a fresh random TCP sequence number.

  When `false` or omitted, the crafted close packet uses the TCP sequence number immediately after the fake generated ClientHello payload.

- `synfin-sni-use-rst` `(boolean)`
  Optional.

  When `true`, `IpManipulator` sends `RST|ACK` instead of `FIN|ACK` for the crafted client-side close packet that is emitted before the fake `SYN`.

  Defaults to `false`.

`0` is a real IPv4 TTL override, not a sentinel for "leave the original TTL unchanged". Omit the TTL field entirely if you want `IpManipulator` to preserve the captured packet TTL for that packet class.

### smuggle-fin settings

- `smuggle-fin` `(boolean)`
  Enables the `smuggle-fin` trick.

- `fin-sni-delay-ms` `(integer)`
  Optional.

  Delay in milliseconds between receiving the expected downstream echoed `FIN|ACK` and replaying the queued packets through the normal pipeline.

  Defaults to `0`.

- `fin-pause-timeout-ms` `(integer)`
  Optional.

  Maximum time in milliseconds that a flow waits for the expected echoed `FIN|ACK`. If the echo does not arrive,
  `IpManipulator` releases that flow's queued packets through the normal pipeline.

  Defaults to `1000`.

- `real-fin-upstream-node` `(string)`
  Required when `smuggle-fin` is enabled.

  Names another node in the same config that will receive the crafted mirrored FIN/ACK packet on the upstream path.

  In the current design this should be a dedicated branch head, not the same node as the normal `next`.

### TCP flag rewrite settings

The current implementation supports these key prefixes:

- `up-tcp-bit-...`
- `dw-tcp-bit-...`

Supported suffixes are:

- `cwr`
- `ece`
- `urg`
- `ack`
- `psh`
- `rst`
- `syn`
- `fin`

Example keys:

- `up-tcp-bit-ack`
- `up-tcp-bit-fin`
- `dw-tcp-bit-psh`
- `dw-tcp-bit-rst`

Supported values are:

- `off`
- `on`
- `toggle`
- `flip`
- `switch`
- `packet->cwr`
- `packet->ece`
- `packet->urg`
- `packet->ack`
- `packet->psh`
- `packet->rst`
- `packet->syn`
- `packet->fin`

`flip` and `switch` are accepted as aliases for `toggle`.

- `preserve-tcp-bitflags` `(boolean)`
  Optional.

  When `true`, a direction with configured TCP-bit rewrite actions backs up the original TCP flags byte as the last byte of the IPv4 packet, then rewrites the live TCP flags.

  A direction with no TCP-bit rewrite actions, while the opposite direction has actions, treats the final packet byte as the backup, restores the TCP flags from it, and shrinks the packet by one byte.

  The direction roles are selected by the configured TCP-bit actions, not by upstream or downstream alone:

  - only upstream has actions: upstream backs up and rewrites; downstream restores and removes the backup byte
  - only downstream has actions: downstream backs up and rewrites; upstream restores and removes the backup byte
  - both directions have actions: both back up and rewrite; neither restores
  - neither direction has actions: no backup or restoration occurs

  Before final egress, eligible whole IPv4 TCP data packets are segmented when
  this byte, port-ghost bytes, or both would make the result exceed
  `GLOBAL_MTU_SIZE`. Each segment carries independently derived live and saved
  flags, its own complete trailers, continuous SYN-aware sequence space, and a
  valid per-segment IPv4 length. A 1500-byte TCP input can therefore be used
  with a 1500-byte WaterWall MTU without reserving operator headroom merely for
  these trailers. An exact-fit buffer is grown when the prospective packet is
  otherwise valid.

#### Stateful SNI composition rules

Only one of `first-sni`, `smuggle-sni`, `overlap-sni`, `synfin-sni`, and
`ech-sni-trick` may be enabled in one `IpManipulator`. Any member of that
stateful set is also rejected with same-instance `sni-blender` or
`packet-duplicate`. Those state machines emit their transcript directly, so a
later stage in the same instance cannot reliably shape that output.

Use two packet nodes when both operations are required:

```text
... -> IpManipulator(stateful SNI only)
    -> IpManipulator(sni-blender and/or packet-duplicate)
    -> ...
```

The stateful SNI node must come first in upstream traversal. Putting packet
duplication before it duplicates input to the state machine and is not
equivalent to duplicating the state machine's final output. `sni-blender` plus
`packet-duplicate` remains valid when no stateful SNI trick is enabled.

#### Rejected TCP-bit compositions

Configuration fails at creation for these combinations:

- any `up-tcp-bit-...` action together with `first-sni`, `smuggle-sni`, `overlap-sni`, `synfin-sni` or `ech-sni-trick`, with or without `preserve-tcp-bitflags`. Upstream TCP-bit actions run before stateful SNI inspection, while the packets those state machines generate and replay do not consistently re-enter TCP-bit processing, so the result would depend on packet flags and on the selected SNI transcript.
- `preserve-tcp-bitflags` together with at least one `up-tcp-bit-...` action and `sni-blender`. That is the encoder direction: the backup byte is appended before SNI Blender creates IPv4 fragments, and the peer restoration path skips fragments and cannot remove that byte.

These remain accepted:

- `preserve-tcp-bitflags` with no TCP-bit actions, which is a no-op encoder
- downstream-only `dw-tcp-bit-...` actions with any stateful SNI trick or with `sni-blender`, because they never touch the upstream flow-opening SYN or the upstream ClientHello
- simple upstream TCP-bit actions with `sni-blender` when `preserve-tcp-bitflags` is off

`preserve-tcp-bitflags` stays unsupported with any future upstream stage that fragments or reshapes a metadata-bearing TCP packet.

### Stateful flow-table settings

- `stateful-flow-limit` `(integer)`
  Optional.

  Hard upper bound on the number of active flows each enabled stateful trick may track. `first-sni`, `smuggle-sni`, `overlap-sni`, `synfin-sni`, `ech-sni-trick` and `smuggle-fin` each get their own bounded table with this limit.

  Valid range in the current implementation:
  - `32` to `1048576`

  Defaults to `65536`.

  The tables never grow past this limit. When a shard is full, `IpManipulator` first reclaims entries whose idle deadline has passed, up to a small fixed budget; if no slot becomes available the admission fails open, the packet is forwarded unchanged, and a rate-limited warning is logged. A live flow is never evicted to admit a new one, which matters for the `ech-sni-trick` and `smuggle-fin` records that own held packet buffers.

  Lookup uses one normalized four-tuple, so a forward packet and its reverse resolve to the same record, the same hash and the same lock, including across workers. Idle expiry uses a per-shard deadline heap, so no packet callback ever scans the whole table.

### Port ghost settings

- `source-port-ghost` `(boolean)`
  Optional.

  When `true`, `IpManipulator` appends the original source port to the end of whole IPv4 TCP or UDP packets, then rewrites the live transport source port to a deterministic pseudo-random high port derived from the original tuple.

- `dest-port-ghost` `(boolean)`
  Optional.

  When `true`, `IpManipulator` appends the original destination port to the end of whole IPv4 TCP or UDP packets, then rewrites the live transport destination port to a deterministic pseudo-random high port derived from the original tuple.

If both are enabled, `IpManipulator` appends the source port bytes first and the destination port bytes second.

## Detailed Behavior

### Packet model

`IpManipulator` only touches packet payload callbacks:

- upstream packet payload goes through `ipmanipulatorUpStreamPayload()`
- downstream packet payload goes through `ipmanipulatorDownStreamPayload()`

Normal stream-style callbacks such as `Init` and `Finish` are intentionally not supposed to run for this tunnel.

### Protocol-number swap

The protocol-swap trick only applies to IPv4 packets.

Behavior:

- if the packet protocol is TCP and `protoswap-tcp` is enabled, the tunnel rewrites the IP protocol field to the configured protocol number
- on downstream, a packet already equal to that configured number is restored to normal TCP
- the same idea applies to `protoswap-udp`
- no replacement value may equal literal TCP (`6`) or UDP (`17`)
- configured TCP and UDP replacement values must remain distinct
- an upstream packet already carrying this node's configured replacement is
  treated as wrapped by an earlier `IpManipulator`; this node restores the real
  protocol, completes checksum work, and forwards it unmapped
- to keep a packet wrapped past a later node, do not enable the same protocol
  swap on that node

TCP uses one reversible `protoswap-tcp` mapping. This also guarantees that the
first and later fragments of one IPv4 datagram receive the same mapped protocol
number. The removed `protoswap-tcp-2` key is rejected with a migration error;
replace it with `protoswap-tcp`.

Upstream tricks run while the packet still carries its real protocol number.
Immediately before normal egress, `IpManipulator` applies port ghost, completes
the IPv4 and transport checksums using that real protocol, swaps the protocol
number, and repairs the IPv4 header checksum. Downstream restores the protocol
before port-ghost restoration or any TCP/TLS trick parses the packet.

### SNI blender

Despite the name, this trick does not rewrite the TLS SNI string itself.

What it actually does is:

- detect an upstream IPv4 TCP packet carrying a TLS ClientHello
- split the IP payload into multiple IP fragments
- shuffle those fragments into random send order
- send the crafted fragments instead of the original packet

Important details from the current code:

- only upstream traffic is affected
- only IPv4 is supported
- only TCP packets are inspected
- only TLS ClientHello packets are fragmented
- already fragmented packets are skipped
- fragment count comes from `sni-blender-packets`
- fragment offsets are rounded to 8-byte boundaries as required by IP fragmentation

Before crafting fragments, the tunnel applies any pending checksum recalculation on the original packet, then marks each crafted packet for checksum recalculation before forwarding.

### first-sni

This trick is upstream-only and only applies to IPv4 TCP packets that begin with a TLS ClientHello carrying an SNI extension.

Behavior:

- detect an upstream TLS ClientHello
- parse the first host-name entry in the TLS server-name extension
- clone the packet and replace only the copied packet's SNI with `first-sni`
- send the modified copy first
- if `first-sni-ttl` is set, update the crafted packet TTL to that value
- if `first-sni-random-tcp-sequence` is `true`, randomize the crafted packet's TCP sequence number
- recompute the crafted packet checksum before send
- then forward the original packet using the original `line->recalculate_checksum` intent
- when replay or final delays are configured, `IpManipulator` keeps a short shared flow record for that TCP 4-tuple and delays later upstream packets on the same flow so they cannot overtake the held original ClientHello

Multi-segment capture starts only when the first segment contains a recognizable
TLS ClientHello start. Unrelated or non-TLS TCP payloads fail open immediately;
they are not held in a speculative prestart queue. Recognized in-order
ClientHellos can still span multiple TCP segments.

IPv4 fragments, including an `MF=1` first fragment and any nonzero-offset later
fragment, never enter First-SNI capture and continue on the normal fail-open
packet path.

When replay/final output is delayed, the held transcript tail is inserted into
a bounded FIFO before later packets. The FIFO uses the flow's one absolute
deadline, so a packet arriving just after that deadline cannot overtake an
older packet merely because the timer callback is late.

If `first-sni` is longer or shorter than the original SNI, the copied packet updates the relevant TLS and IPv4 length fields.

If the ClientHello contains a TLS 1.3 `pre_shared_key` extension with PSK binders and the configured `first-sni` would actually change the SNI bytes, the trick skips crafting the fake packet and leaves the original packet path alone. `IpManipulator` does not own the PSK secret needed to recompute valid binders.

### smuggle-sni

This trick is upstream-only and applies to IPv4 TCP packets carrying a TLS ClientHello record with an SNI extension.

Behavior:

- captures and reassembles a TLS ClientHello record across single or multi-segment TCP payloads (up to 16 segments / 16 KB) on the 4-tuple
- generates a fake TLS ClientHello of total record length `L` matching the captured ClientHello total record length `R`
- constructs a multi-segment fake batch that strictly preserves original TCP segment boundaries, original TCP segment payload lengths, original TCP sequence numbers, and any trailing payload bytes beyond the ClientHello record
- sends the original captured ClientHello segments immediately to `real-sni-upstream-node` in order
- schedules the generated fake segment batch to the normal next tunnel after `smuggle-sni-delay-ms`
- if record length mismatch (`L != R`), segment sequence discontinuity, timeout, or generation failure occurs, `smuggle-sni` fails open immediately, forwarding original captured packets to the normal path without delay or modification

Later flow packets inside the delay window enter the same bounded,
absolute-deadline FIFO. The fake transcript is scheduled ahead of that FIFO,
and `FIN`/`RST` stays behind already queued data.

If the ClientHello contains a TLS 1.3 `pre_shared_key` extension with PSK binders and the configured `smuggle-sni` would actually change the SNI bytes, the trick skips crafting the fake packet and leaves the original packet on the normal path. `IpManipulator` does not have the PSK secret required to recompute valid binders.

### smuggle-fin

This trick is upstream-only and only applies to whole IPv4 TCP packets that already carry ACK and transport payload.

Behavior:

- clone the original IPv4 and TCP headers into a header-only packet
- swap the copied packet's source and destination IPv4 addresses
- swap the copied packet's TCP source and destination ports
- turn the copied packet into a pure `FIN|ACK` packet with no transport payload
- mirror the TCP sequence and acknowledgement numbers from the original packet so the crafted packet looks like the reverse direction
- send the crafted packet immediately through `real-fin-upstream-node`
- pause the flow on its owner worker inside `IpManipulator`
- queue later upstream and downstream packets on that owner worker instead of forwarding them immediately, including matching reverse packets that arrive on another worker
- ignore the first downstream packet that exactly matches the crafted `FIN|ACK`
- wait `fin-sni-delay-ms`
- replay the queued packets in arrival order through the normal pipeline
- preserve each queued packet's checksum-recalculation intent independently
- keep the remembered flow in the internal table after that success so the expected echoed `FIN|ACK` is not treated as a real connection-closing FIN event for this trick

Upstream replay restarts at the upstream entry because `smuggle-fin` is the
first upstream stage. Downstream replay resumes immediately after
`smuggle-fin`, because protocol and port-ghost restoration already ran before
the packet was queued and must not run twice.

Packets without TCP payload, packets that are already `SYN`, `FIN`, or `RST`, and non-TCP or fragmented IPv4 packets are left alone.

### TCP flag rewriting

The TCP-bit trick only applies to valid IPv4 TCP packets.

For each configured bit action, the tunnel can:

- force the bit off
- force the bit on
- toggle it
- copy the value of another TCP flag from the same packet

If any flag changes in simple mode (without `preserve-tcp-bitflags`), the TCP flags byte is rewritten and the TCP checksum is updated incrementally in place with `updateIpv4TransportChecksum16()`. Simple flag changes preserve any pre-existing checksum recalculation flag without creating a new request.

This happens independently on upstream and downstream using the `up-...` and `dw-...` setting families.

If `preserve-tcp-bitflags` is enabled:

- rewrite directions append one extra byte at the end of the IPv4 packet carrying the original TCP flags before applying any configured TCP-bit actions
- restore directions copy that final byte back into the TCP flags field and reduce the IPv4 packet length by one byte
- only upstream actions means upstream backs up and rewrites while downstream restores
- only downstream actions means downstream backs up and rewrites while upstream restores
- actions in both directions means both directions back up and rewrite, so neither restores
- no actions in either direction means this option does not add or remove a backup byte
- fragmented IPv4 packets are skipped so the tunnel only operates on whole TCP packets with a real TCP header and transport payload

### Stateful flow tables

Every stateful trick keeps its records in its own bounded, sharded flow table:

Retained packets are pinned to the worker that opened their capture, delay
barrier, or held-packet group. A same-tuple packet arriving on another worker
makes that trick fail open for the flow; it is forwarded normally on its own
worker. This is relevant only when an upstream producer does not preserve the
shared flow affinity. `StreamToPackets` does preserve it by re-affinitizing each
decoded packet from its inner tuple before forwarding it.

- the canonical key normalizes the two endpoints, so a forward packet and its
  reverse select the same hash, the same shard and the same record
- the shard count follows the worker count, capped at 64, and the configured
  `stateful-flow-limit` is partitioned across shards so the shard limits sum to
  it exactly
- lookup is average O(1) through hash buckets and idle expiry pops a per-shard
  deadline heap, so no packet callback scans the whole table
- the per-tunnel hash seed comes from `secureRandomBytes()`; tunnel creation
  fails when no secure seed is available, because a predictable hash would let
  an attacker pick tuples that all land in one bucket
- a record pointer is only valid while its shard mutex is held, so timers and
  cross-worker messages carry the normalized tuple plus a flow generation
- record destructors run under the shard mutex and only dispose of owned
  buffers; they never forward a packet or call into a tunnel

Overlap-SNI and SynFIN-SNI holds are bounded by per-flow fail-open timers keyed
by the normalized tuple plus a nonzero hold generation. Timeout releases the
held segment unchanged outside the shard lock. An upstream close releases either
trick's live hold, and Overlap-SNI also releases it on a downstream close.
If idle expiry or table teardown removes the record before its timer callback,
the record destructor deliberately disposes of the held packet instead of
forwarding from under the shard lock or during shutdown.

First-SNI, Smuggle-SNI, and Overlap-SNI delay windows use a per-flow FIFO capped
at 16 packets and 256 KiB. A tunnel-wide generation binds the one release action
to both the tuple and the exact barrier instance, so a stale timer cannot release
a reused tuple. Release detaches the batch under the shard lock and forwards it
outside the lock. Count/byte exhaustion fails open in order: queued packets are
detached first, followed by the current packet. Flow reset, timeout, and table
destruction recycle all retained buffers.

Every delayed release has a fail-open path: if its timer cannot be armed, held
bytes are flushed immediately and in order instead of being stranded.

`smuggle-fin` additionally keeps a per-worker paused-flow registry holding one
tuple plus pause generation, so the rule that a worker does not start a second
pause while it already owns one no longer requires a full-table scan. The
registry is only written by the flow-owner worker and is validated against the
table before use, so a cross-worker release simply leaves an entry that the
owner worker clears on its next packet.

### Port ghost tailing

The port-ghost trick only applies to whole IPv4 TCP or UDP packets.

When `source-port-ghost` and/or `dest-port-ghost` are enabled:

- the selected original TCP or UDP port bytes are appended at the end of the transport packet payload
- the matching live TCP or UDP port fields are rewritten to deterministic pseudo-random high ports derived from the original tuple
- downstream packets that still carry those transported port bytes restore the original live port fields and shrink the packet back to its original length
- IPv4 total length is increased to cover the appended ghost bytes
- UDP length is also increased when the packet is UDP
- `line->recalculate_checksum` is set so a later packet writer rebuilds checksums
- fragmented IPv4 packets are skipped
- ordinary and crafted whole TCP data packets are segmented before final
  trailer-bearing egress whenever necessary; every segment carries exactly one
  complete port-ghost trailer and, when configured, one independently
  restorable saved-flags byte, and remains within `GLOBAL_MTU_SIZE`
- `SYN` and `CWR` are placed only on the first segment, `FIN` and `PSH` only on
  the final segment, and `ACK`/applicable `ECE` on every segment; later sequence
  numbers account for SYN consuming one sequence number
- exact-fit buffers are grown when the final packet is otherwise valid
- oversized UDP datagrams, `RST`, unsupported `URG`, and other packets that
  cannot be safely transport-segmented are rate-limited-log-and-drop cases;
  IpManipulator does not add IPv4 fragmentation or reassembly, so UDP needs
  operator-provided MTU headroom
- dedicated real-SNI, mirrored-FIN, and overlap-SNI server-hello helper branches
  preserve their original tuples and do not receive a port-ghost trailer

## Notes And Caveats

- This tunnel is for raw packet chains, not normal byte-stream chains.
- The node advertises `kNodeLayer3`; its previous and next neighbor constraints
  remain `kNodeLayerAnything` for flexible packet-chain composition.
- Only IPv4 packets are modified by the current implementation.
- `first-sni` is upstream-only, rewrites the first TLS host-name entry in the crafted copy, and immediately fails open on traffic without a recognizable ClientHello start.
- `smuggle-sni` is upstream-only and sends the real matching ClientHello immediately to `real-sni-upstream-node`, then delays the crafted `smuggle-sni` copy to the normal `next` branch.
- `smuggle-fin` is upstream-only and injects a crafted mirrored FIN/ACK packet to `real-fin-upstream-node`, then temporarily queues later packets on the flow-owner worker until the expected downstream echo is seen and the optional `fin-sni-delay-ms` window expires.
- `sni-blender` is upstream-only. The downstream half of that trick is currently a no-op.
- `ech-sni-trick` capture is sequence aware rather than ordinal based, is bounded to 16 packets and a 16384-byte TLS record, ignores ACK-only packets, and fails open on timeout, gaps, limits and any inner-SNI mismatch.
- More than one stateful SNI trick, or a stateful SNI trick with same-instance
  SNI Blender/packet duplication, is rejected. Upstream TCP-bit actions are
  also rejected with stateful SNI, and preserved upstream TCP-bit metadata is
  rejected with `sni-blender`.
- Every stateful trick is bounded by `stateful-flow-limit`; a full table fails open with a rate-limited warning instead of evicting a live flow.
- The tunnel relies on later packet-writing code to honor `line->recalculate_checksum` and rebuild packet checksums.
- `sni-blender-packets` is required when `sni-blender` is enabled and must be
  between `2` and `16`.
- `first-sni-random-tcp-sequence` affects only the crafted `first-sni` copy, not the original packet.
- The struct contains `trick_sni_blender_packets_delay_max`, but current JSON parsing does not expose or use it.
