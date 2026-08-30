<!--
Documentation version: 152
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/IpManipulator.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/IpManipulator.mdx, and all files must keep the same documentation version.
-->

# IpManipulator Node

`IpManipulator` is a packet tunnel that mutates IPv4 packets in place.

It is meant for layer-3 chains where the payload is already a raw IP packet, not a normal TCP stream line.

The current implementation provides these classes of tricks:

- protocol-number swapping
- decoy TLS ClientHello copy sent before the real one (`first-sni`)
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
- Can hold the third upstream packet only when it begins an incomplete TLS ClientHello, overlap it with a crafted fake ClientHello after the contiguous completing packet arrives, emit a fake TCP SYN on the same 4-tuple, and then flush the remaining real ClientHello bytes. If completion does not arrive within the overlap hold timeout, the held packet is released unchanged.
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

  Duplicates each final outgoing packet this many times, then sends the original packet once. Values must be between 1
  and 16.

  This is applied as the last step of `IpManipulator`, after all other enabled tricks have finished shaping the packet.

### first-sni settings

`first-sni` puts one or more decoy copies of the client's own TLS ClientHello,
with only the host name replaced, on the wire ahead of the real ClientHello of
the same TCP connection. The full packet flow is described under "first-sni" in
"Detailed Behavior".

- `first-sni` `(string)`
  Enables the `first-sni` trick and sets the host name written into the decoy TLS ClientHello copies.

  Must not be empty and must fit the 16-bit TLS length fields, so `1` to `65535` bytes. The bytes are copied verbatim into the copy's `server_name` extension; they are not validated as a host name, so choose a name that is plausible and uninteresting on the inspected path.

  Only the first `host_name` entry of the copy is rewritten. The real ClientHello is never modified.

  The length difference between this value and the real host name changes the copy's TCP payload length, its TLS record length and its IPv4 total length. No padding extension is shrunk or grown to compensate, so a decoy whose name length differs from the real one is a differently sized packet.

- `first-sni-ttl` `(integer)`
  Optional.

  When present, the crafted decoy packets are sent with this IPv4 TTL instead of the TTL of the original ClientHello.

  Valid range: `0` to `255`

  This is the usual way to keep the decoy away from the destination server: choose a TTL that is large enough to reach the inspecting device but too small to reach the server, so an intermediate router discards the decoy with an ICMP time-exceeded reply and only the real ClientHello arrives. The correct value is path dependent and has to be measured, for example with a traceroute to the destination.

  `0` is a real TTL override, not a sentinel. Omit the field entirely to keep the original TTL.

  When omitted, the decoy keeps the TTL of the packet it was cloned from and will normally reach the server; see `first-sni-random-tcp-sequence` and the caveats under "Detailed Behavior".

- `first-sni-count` `(integer)`
  Optional.

  Number of decoy ClientHello copies sent before the original ClientHello. Values must be between 1 and 16.

  Valid range: `1` through `16`

  Defaults to `1`.

  Every copy is crafted separately from the same captured ClientHello, so all copies are byte identical except for a randomized TCP sequence number when `first-sni-random-tcp-sequence` is enabled. Raising this value increases the chance that an inspecting device that samples or loses packets still observes a decoy, at the cost of sending the ClientHello payload that many extra times.

  When `first-sni-replay-delay` is greater than `0`, the `count - 1` additional copies are all crafted up front and held in memory until their scheduled send time, so keep the value modest.

- `first-sni-replay-delay` `(integer)`
  Optional.

  Delay in milliseconds between consecutive decoy copies after the first one.

  Valid range: `0` or greater

  Defaults to `0`.

  Only meaningful when `first-sni-count` is greater than `1`. Copy 1 is always sent immediately inside the packet callback; copy `i` is scheduled at `(i - 1) * first-sni-replay-delay` milliseconds after that. With `0`, all copies leave back to back in one callback with no pacing between them.

  A nonzero value makes the trick stateful for that flow: the original ClientHello and every later upstream packet of the same 4-tuple are held in a per-flow FIFO until the schedule completes.

- `first-sni-final-delay` `(integer)`
  Optional.

  Delay in milliseconds between the last decoy copy and the original ClientHello.

  Valid range: `0` or greater

  Defaults to `0`.

  The original ClientHello is released `(first-sni-count - 1) * first-sni-replay-delay + first-sni-final-delay` milliseconds after the first decoy. Use it to give an inspecting device time to reach a verdict from the decoy before the real host name appears on the same connection. Any nonzero value also delays every other upstream packet of that flow, including the client's own ACKs, so keep the total in the tens of milliseconds.

  Startup fails when `(first-sni-count - 1) * first-sni-replay-delay`, or that value plus `first-sni-final-delay`, exceeds the supported unsigned 32-bit millisecond range.

- `first-sni-random-tcp-sequence` `(boolean)`
  Optional.

  When `true`, each crafted decoy packet gets a fresh random 32-bit TCP sequence number before it is sent.

  When `false` or omitted, the decoy keeps the original ClientHello's TCP sequence number, so both packets claim the same position in the TCP stream.

  Defaults to `false`.

  A random sequence number places the decoy far outside the server's receive window, so a conforming TCP stack discards it and answers at most with a duplicate or challenge ACK, while a middlebox that reassembles by direction without validating sequence numbers still parses it as this connection's ClientHello. It is the alternative to `first-sni-ttl` when the hop distance to the server is unknown, and it has no effect on inspection devices that do track sequence numbers and windows.

  Only the decoy is affected. The original ClientHello always keeps its real sequence number.

### smuggle-sni settings

- `smuggle-sni` `(string)`
  Enables the trick and supplies the host name for the generated ClientHello
  sent on the normal branch. The effective accepted length is `1` through `255`
  bytes because the internal `TlsClient` generator enforces the TLS host-name
  limit during node creation.

  Omit this setting to disable the trick; it has no host-name default.

  The generated record is not the real ClientHello with only SNI replaced. It
  uses the internal `TlsClient` fingerprint, default ALPN order `h2`,
  `http/1.1`, and has `x25519mlkem768` disabled. A flow is transformed only when
  this complete generated record has exactly the same byte length as the real
  ClientHello record.

- `smuggle-sni-delay-ms` `(integer)`
  Optional.

  Time after successful capture at which the generated packet batch becomes
  eligible for transmission on the normal `next` branch. The real captured
  batch is sent to `real-sni-upstream-node` first.

  Valid range: `0` or greater

  Defaults to `0`.

  This setting does not control how long later upstream packets are retained.
  After a successful transcript, Smuggle-SNI keeps a separate ordering window
  until `max(50000, smuggle-sni-delay-ms + 1)` milliseconds after capture. At
  `0`, the fake batch is sent synchronously, but later packets can still wait
  until the 50-second window ends.

- `real-sni-upstream-node` `(string)`
  Required when `smuggle-sni` is enabled.

  Names the auxiliary upstream branch that receives the original captured
  ClientHello packets after capture completes. The named node must exist, must
  not be this `IpManipulator`, and at chain construction must differ from the
  normal `next` and be available for binding from this node.

  The branch topology, not this setting, determines which devices and endpoint
  receive the real ClientHello and whether it later rejoins the normal path.

`smuggle-sni` requires a normal top-level `next` in addition to the helper.
The shared `stateful-flow-limit` bounds its flow table, accepts `32` through
`1048576`, and defaults to `65536`. The 50 ms speculative prestart timeout,
1500 ms fragmented-record timeout, 50-second ordering window, capture limits,
generated fingerprint, and packet headers have no Smuggle-SNI-specific
settings.

### overlap-sni settings

`overlap-sni` writes one TCP sequence range twice: first with the real beginning
of the client's ClientHello, then, after a fake TCP `SYN`, with a generated
ClientHello carrying a different host name. The full packet flow is described
under "overlap-sni" in "Detailed Behavior".

- `overlap-sni` `(string)`
  Enables the `overlap-sni` trick and sets the host name written into the generated TLS ClientHello.

  The effective accepted length is `1` to `255` bytes. `IpManipulator` first stores the value in a 16-bit TLS-length field, but the internal `TlsClient` used to generate the packet enforces the stricter 255-byte TLS host-name limit during node creation. A longer value therefore prevents startup; it does not become a per-flow fail-open case.

  The generated hello is a real ClientHello built by that internal client, not a copy of the client's own hello. It follows the internal client's TLS fingerprint and its default ALPN list (`h2`, `http/1.1`), and it is created with the post-quantum key share disabled so it stays small enough to fit inside the real ClientHello.

  Let `G` be the generated hello length. A longer configured host name normally increases `G`, enlarging the overwritten TCP range and making the trick's requirement that the real SNI begin at or after offset `G` harder to satisfy. At runtime, a generated hello longer than `900` bytes or longer than the two captured real payloads combined is rejected and those real packets fail open unchanged.

- `overlap-sni-delay-ms` `(integer)`
  Optional.

  Delay in milliseconds between the immediately emitted real prefix/fake `SYN` pair and the generated ClientHello. Any real continuation packets are scheduled at additional `2` ms intervals.

  Valid range: `0` or greater

  Defaults to `0`.

  It also contributes to the flow's absolute delay-window deadline:
  `max(5000 ms, overlap-sni-delay-ms + 5 ms)` after the transcript is built.
  Values from `0` through `4995` therefore change the spacing before the crafted
  tail but not the five-second deadline for later upstream packets. Larger
  values extend that deadline. While the window is open, later upstream packets
  are held in a bounded FIFO and released together at the deadline; they do not
  each receive a fresh copy of the configured delay. The crafted overlap tail is
  always ordered ahead of that FIFO.

  Increasing the delay gives an observer more time to process the fake `SYN`
  before packet `X` arrives and reduces the chance that packet `X` overtakes
  packet `Y` in the network. It also increases latency and makes TCP
  retransmissions or connection timeouts more likely.

- `overlap-sni-hold-timeout-ms` `(integer)`
  Optional.

  Maximum time in milliseconds to hold the selected incomplete ClientHello segment while waiting for the immediately following sequence-contiguous payload segment. Expiry fails open by releasing the held segment unchanged and moving the flow to passthrough.

  Valid range: greater than `0`

  Defaults to `50`.

  The value bounds how long one client packet may be stalled inside `IpManipulator`. Raising it helps only when the next ClientHello segment is delayed by more than the default `50` ms; if it approaches the sender's retransmission timeout, a retransmission can arrive first and make the pair fail open.

- `overlap-sni-syn-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the fake overlap-sni TCP `SYN` packet. No other crafted packet is affected.

  Valid range: `0` to `255`

  A low value can let an inspection device near `IpManipulator` observe the fake `SYN` while causing a later router to expire it before the destination. This reduces the chance that the server reacts to a `SYN` inside an established connection. The usable value is path- and placement-dependent.

  `0` is a real TTL override, not a sentinel, and normally prevents the packet from travelling beyond the local link. When the field is omitted, the fake `SYN` copies the held segment's TTL. The setting changes only the fake `SYN`; packet `Y`, packet `X`, and the real continuation packets retain their template TTLs.

The shared `stateful-flow-limit` setting also bounds the number of overlap flow
records. If the table cannot admit the opening `SYN`, that flow remains
untracked and passes unchanged.

### ech-sni-trick settings

`ech-sni-trick` coordinates with `TlsClient` to expose a decoy ClientHello as
an out-of-order TCP segment before the real outer ClientHello is released. It
does not encrypt ECH or rewrite the real ClientHello. The complete packet flow
is described under "ech-sni-trick" in "Detailed Behavior".

- `ech-sni-trick` `(string)`
  Enables the trick and identifies the host name that must appear in the
  embedded decoy ClientHello.

  Valid length: `1` through `255` bytes

  Configure the same byte string in `TlsClient.settings.ech-sni-trick` for the
  corresponding flow. `TlsClient` generates a complete decoy ClientHello with
  this SNI and embeds it, unencrypted, in the payload field of a GREASE
  `encrypted_client_hello` extension. `IpManipulator` does not generate or
  modify that hello; it searches the captured outer ClientHello for exactly one
  complete embedded ClientHello whose first `host_name` entry matches this
  setting byte for byte.

  Matching is case-sensitive and performs no DNS-name normalization. Changing
  this value only in `IpManipulator` makes the runtime check fail and the real
  ClientHello pass unchanged. Changing it in both nodes changes the decoy SNI
  and usually changes the embedded ClientHello length, its position within the
  outer ClientHello, and the resulting out-of-order packet size.

  This is GREASE camouflage, not real encrypted ECH. Both the real outer SNI
  and the decoy ClientHello remain present as clear bytes on the wire.

- `data-shard-1-delay` `(integer)`
  Optional.

  Delay in milliseconds from sending the out-of-order decoy segment to
  releasing the first captured original packet.

  Valid range: `0` or greater

  Defaults to `0`.

  Increasing this delay gives a packet-oriented observer more time to parse and
  classify the decoy before any lower-sequence outer ClientHello bytes arrive.
  It also leaves a longer hole at the destination TCP receiver and increases
  the chance of duplicate ACKs, SACKs, retransmissions, or handshake timeout.
  At `0`, the decoy is still emitted first, but the first original follows
  immediately on the same worker.

- `data-shard-2-delay` `(integer)`
  Optional.

  Additional delay in milliseconds after original packet 1 is released and
  before original packets 2 through N are released.

  Valid range: `0` or greater

  Defaults to `0`.

  Packets 2 through N are emitted consecutively in their captured order; this
  setting does not pace them individually. A one-packet capture ignores it.
  Increasing it separates the first original shard from the rest, but also
  prolongs TCP reordering and TLS-handshake latency.

The two delays are relative: the decoy leaves at time `T`, original packet 1 at
`T + data-shard-1-delay`, and originals 2 through N at
`T + data-shard-1-delay + data-shard-2-delay`. Their sum must fit the supported
unsigned 32-bit millisecond range. The shared `stateful-flow-limit` setting
bounds ECH flow records and defaults to `65536`. This trick also requires a
normal top-level `next`; it has no TTL, random-sequence, packet-count, or helper-
branch setting.

### synfin-sni settings

- `synfin-sni` `(string)`
  Enables the trick and supplies the host name for the generated decoy
  ClientHello. The effective accepted length is `1` through `255` bytes because
  the internal `TlsClient` that generates the record enforces the TLS host-name
  limit.

  The generated record uses the internal `TlsClient` defaults, including ALPN
  order `h2`, `http/1.1`, with `x25519mlkem768` disabled. It is not a copy of the
  real client's fingerprint. Its complete TLS record must be no more than 900
  bytes and must fit before the real SNI position in the selected two-segment
  ClientHello; see "synfin-sni" under "Detailed Behavior".

- `synfin-sni-hold-timeout-ms` `(integer)`
  Optional.

  Maximum time in milliseconds to hold an incomplete first ClientHello segment while waiting for its contiguous completion. Expiry fails open by releasing the segment unchanged.

  Valid range: greater than `0`

  Defaults to `50`.

- `synfin-sni-additional-range-min` `(integer)`
  Optional.

  Requested minimum number of bytes by which the real-first overlap interval is
  extended beyond the generated ClientHello length.

  When present without `synfin-sni-additional-range-max`, this value is also used
  as the requested fixed extra overlap length; runtime safety clamping can still
  reduce it.

  Valid range: `0` to `65535`

  Defaults to `0`.

- `synfin-sni-additional-range-max` `(integer)`
  Optional.

  Requested maximum extension of the real-first overlap interval. If only this
  maximum is configured, the minimum remains `0`. The minimum must not exceed
  the maximum.

  `IpManipulator` clamps both ends to what the captured ClientHello permits, then
  chooses one inclusive random value per successful flow. The resulting real-
  first packet ends no later than the first byte of the real SNI and no later
  than the captured data. A value smaller than `5` produces that many random
  filler bytes in the later fake view; a value of at least `5` produces one TLS
  1.2-style Application Data record header followed by random bytes. The
  configured minimum is therefore a request, not a guarantee, when the safe
  range is smaller.

  Valid range: `0` to `65535`

  Defaults to `0`.

- `synfin-sni-syn-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the crafted `SYN` packet.

  Valid range: `0` to `255`

  When omitted, the fake `SYN` normally keeps the opening `SYN`'s TTL. If the
  opening-header copy could not be retained, construction falls back to the held
  ClientHello segment and its TTL.

- `synfin-sni-fin-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the crafted close packet (`FIN|ACK` by default, `RST|ACK` when `synfin-sni-use-rst` is enabled).

  Valid range: `0` to `255`

  When omitted, the close packet keeps the held ClientHello segment's TTL.

- `synfin-sni-fake-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of packet `X`, the complete generated
  ClientHello at the original first-data sequence number.

  This does not affect the real-first packet, the optional random/TLS-looking
  filler packet after `X`, or the real continuation packets. Those keep the TTL
  of their own header templates.

  Valid range: `0` to `255`

  When omitted, packet `X` keeps the held ClientHello segment's TTL.

- `synfin-sni-random-syn-checksum` `(boolean)`
  Optional.

  When `true`, the fake `SYN` receives arbitrary randomized IPv4 and TCP
  checksum fields instead of recomputed valid values. They will normally be
  invalid, although a random field can coincidentally equal the correct value.

  Defaults to `false`.

- `synfin-sni-random-fin-checksum` `(boolean)`
  Optional.

  Applies the same arbitrary-checksum behavior to the synthetic close packet.
  It does not affect packet `Y`, packet `X`, filler, or real continuations.

  Defaults to `false`.

- `synfin-sni-random-syn-sequence` `(boolean)`
  Optional.

  When `true`, the fake `SYN` uses a fresh random 32-bit TCP sequence number.
  Packet `X` still starts at the real first-data sequence, so it will no longer
  be `SYN.seq + 1` except by chance.

  Defaults to `false`, which uses `S - 1` when the selected real ClientHello
  starts at sequence `S`.

- `synfin-sni-random-fin-sequence` `(boolean)`
  Optional.

  When `true`, the synthetic close uses a fresh random 32-bit sequence number.
  This may keep it outside the destination's receive window, but also makes the
  close less coherent to a sequence-aware middlebox.

  Defaults to `false`, which places the close at `S + Y`, immediately after the
  entire real-first/fake-plus-filler overlap interval, not merely after the
  generated ClientHello.

- `synfin-sni-use-rst` `(boolean)`
  Optional.

  When `true`, `IpManipulator` sends `RST|ACK` instead of `FIN|ACK` for the crafted client-side close packet that is emitted before the fake `SYN`.

  Defaults to `false`.

`0` is a real IPv4 TTL override, not a sentinel for "leave the original TTL unchanged". Omit the TTL field entirely if you want `IpManipulator` to preserve the captured packet TTL for that packet class.

The complete replacement transcript is emitted synchronously and back to back;
none of these settings adds pacing. The shared `stateful-flow-limit` bounds the
SynFIN flow table and defaults to `65536`. This trick also requires a normal top-
level `next` and has no helper-branch setting.

### smuggle-fin settings

- `smuggle-fin` `(boolean)`
  Enables the trick when `true`. The feature does not parse TLS or SNI despite
  the `fin-sni-delay-ms` setting name. Any eligible IPv4/TCP data
  packet can trigger it.

  Defaults to `false`/absent.

- `fin-sni-delay-ms` `(integer)`
  Optional.

  Delay in milliseconds between consuming the exact downstream echoed
  `FIN|ACK` and replaying the queued packets through the normal pipeline.

  Valid range: `0` or greater

  Defaults to `0`.

  This is a post-echo delay, not the maximum pause. The original
  `fin-pause-timeout-ms` timer remains armed; if it expires first, it releases
  the queue early. At `0`, release is immediate on the owner worker (or queued
  immediately to that worker when the echo arrived elsewhere).

- `fin-pause-timeout-ms` `(integer)`
  Optional.

  Hard maximum pause measured from the triggering data packet. If no exact echo
  arrives, or the post-echo delay would run longer, this deadline releases the
  queued flow through the normal pipeline. If the timer cannot be armed, the
  queue is released immediately instead.

  Valid range: greater than `0`

  Defaults to `1000`.

- `real-fin-upstream-node` `(string)`
  Required when `smuggle-fin` is enabled.

  Names the auxiliary upstream branch that receives the synthetic reverse
  `FIN|ACK`. The named node must exist, must not be this `IpManipulator`, and at
  chain construction must differ from the normal `next` and be available for
  binding from this node.

  The branch topology must cause a semantically matching `FIN|ACK` to return on
  this `IpManipulator`'s downstream path if echo-confirmed release is expected.
  A normal TCP ACK response to the FIN does not match; see the detailed packet
  flow below.

`smuggle-fin` requires a normal top-level `next` in addition to the helper
branch. The shared `stateful-flow-limit` bounds its flow table and defaults to
`65536`. There is no setting for the mirrored FIN's TTL, sequence numbers,
flags, or checksum: they are derived from the triggering packet and its checksum
is recomputed.

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

This trick is upstream-only and only applies to IPv4 TCP packets that carry a
TLS ClientHello with a `server_name` extension. Downstream traffic is never
touched.

#### What the trick is for

Many inspection systems classify a TLS connection from the first ClientHello
they see on a 4-tuple and keep that verdict for the rest of the connection.
`first-sni` exploits that by putting a decoy ClientHello on the wire first: an
otherwise byte-identical copy of the client's own ClientHello in which only the
host name has been replaced. A device that latches onto the first ClientHello
records the decoy name, while the destination server is expected to receive only
the real ClientHello.

This is the classic "fake packet" desynchronization idea applied to the SNI
field. It does not obfuscate, fragment, split or reorder the real ClientHello;
the real packet still travels intact, exactly once, at its real sequence number.

#### Packet flow for a single-segment ClientHello

With `first-sni-count` at its default of `1` and both delays at `0`, everything
happens inside one upstream packet callback:

1. The TCP handshake is untouched. `SYN`, `SYN|ACK` and the first `ACK` pass
   through unchanged; the trick has no interest in them.
2. The client sends its ClientHello in one segment: sequence `S`, payload length
   `L`, normally `PSH|ACK`.
3. `IpManipulator` parses that payload. It requires a complete TLS
   `handshake (0x16)` record whose ClientHello message exactly fills the record
   body, containing a `server_name` extension with at least one `host_name`
   entry. A payload that only begins such a record enters the multi-segment
   capture described below; anything else fails open.
4. The packet is cloned into a new buffer, and only the first `host_name` string
   is replaced by the configured value. To keep the copy structurally valid,
   six length fields are rewritten by the same delta: `host_name` length,
   server-name-list length, `server_name` extension length, extensions length,
   ClientHello handshake length, TLS record length, plus the IPv4 total length.
5. Everything else in the copy is the original's bytes: the same IPv4
   identification, flags and TTL, the same TCP ports, sequence number,
   acknowledgement number, window, flags and options, the same TLS version,
   `random`, session id, cipher list, and every other extension.
6. `first-sni-ttl`, when configured, overwrites the copy's IPv4 TTL, and
   `first-sni-random-tcp-sequence`, when enabled, overwrites the copy's TCP
   sequence number with a fresh random 32-bit value.
7. The decoy is sent upstream first with recomputed IPv4 and TCP checksums.
   `first-sni` has no bad-checksum option; both packets always leave with valid
   checksums.
8. The original ClientHello is then forwarded unchanged, also with recomputed
   checksums.

On the wire the destination sees, in order: the decoy ClientHello, then the real
ClientHello, both on the same 4-tuple.

#### Sequence numbers and why the decoy must not reach the server

Unless `first-sni-random-tcp-sequence` is enabled, the decoy carries the real
ClientHello's sequence number `S`, so both segments claim the same position in
the TCP byte stream. If the configured name is longer than the real one by `d`
bytes, the decoy covers `S` to `S + L + d` while the real packet covers `S` to
`S + L`; if it is shorter, the decoy covers less. The two segments therefore
overlap, and a receiver keeps whichever copy its overlap handling accepts.

That is exactly the point for an inspecting device, and exactly the problem for
the server. If the decoy arrives at the destination as valid in-window data, a
typical TCP stack delivers the decoy bytes to the TLS server and treats the
later real segment as a duplicate, so the server answers the decoy host name.
The client's TLS stack computes its transcript over its own ClientHello, so such
a connection normally fails with a certificate or handshake error rather than
carrying traffic. Configure at least one of the two mechanisms that keep the
decoy away from the server:

- `first-sni-ttl` set low enough that a router between the inspection point and
  the server discards the decoy. The correct value is path dependent; the
  discarding router will normally return ICMP time-exceeded toward the client
  address.
- `first-sni-random-tcp-sequence`, which places the decoy far outside the
  server's receive window. A conforming stack discards out-of-window data and
  answers at most with a duplicate or challenge ACK, while an inspector that
  reassembles by direction without checking sequence numbers still parses the
  decoy as this connection's ClientHello.

Both can be combined. Leaving both unset is only sensible when the configured
value is identical to the real host name, which turns the copy into a plain
duplicate segment and removes the decoy effect.

What an intermediate device reconstructs depends on how it handles the overlap:
a per-packet inspector sees two ClientHellos and normally acts on the first, a
reassembling inspector that keeps first-arrived bytes for a sequence range also
ends up with the decoy, and an inspector that validates windows and TTLs, or
that prefers later data for an overlapping range, sees the real name. None of
this is guaranteed by any standard, so the result is path specific.

#### Repeats and delays

- `first-sni-count` decides how many decoys are sent. Copy 1 always leaves
  synchronously, ahead of everything else.
- With `first-sni-replay-delay` at `0`, all copies are crafted and sent back to
  back in the same callback with no pacing.
- With a nonzero `first-sni-replay-delay`, copies 2 to N are scheduled at
  `1 x delay`, `2 x delay`, ... `(N-1) x delay` after copy 1, and are all crafted
  in advance.
- The original ClientHello is released after
  `(count - 1) * replay-delay + final-delay` milliseconds, that is, immediately
  after the last decoy when `first-sni-final-delay` is `0`.
- While that window is open, later upstream packets of the same 4-tuple, ACKs
  and `FIN`/`RST` included, are queued behind the held original in a per-flow
  FIFO so nothing overtakes the delayed ClientHello. Downstream packets are
  never delayed.
- The FIFO holds at most 16 packets and 256 KiB per flow. Overflow, a packet of
  the flow arriving on another worker, or a timer that cannot be armed all fail
  open in order: queued packets are flushed first, then the current packet.
- A payload-free opening `SYN` on the same 4-tuple resets the flow record, so a
  reused tuple starts a fresh, delay-free flow. Anything the previous generation
  still held is discarded rather than forwarded.
- With both delays at `0` no timer is armed and no delayed state is created at
  all; the trick is then purely synchronous.
- The per-flow record is bounded by `stateful-flow-limit` and expires after 20
  minutes of inactivity. If no record can be admitted, the schedule collapses:
  a warning is logged and the pending copies plus the original are sent
  immediately, still in the documented order.

#### Multi-segment ClientHello

When the ClientHello does not fit in one segment, `first-sni` captures it. The
capture starts only on a segment whose payload actually begins a recognizable
ClientHello record, so unrelated or non-TLS payloads fail open immediately and
are never held in a speculative prestart queue. Strictly contiguous following
segments are appended until the TLS record is complete, bounded by 16 packets, a
16384-byte record and a 1500 ms timeout since the last accepted segment.

On completion the trick operates on one assembled packet made of the first
segment's IPv4 and TCP headers followed by all captured payload bytes. The
individual original segments are dropped, not forwarded. Two consequences are
visible on the wire: the destination receives the real ClientHello as one larger
segment starting at the first segment's sequence number instead of the client's
original segment pattern, and that coalesced packet carries the first segment's
TCP flags, window and acknowledgement number. Byte content and sequence
continuity are preserved. If the assembled packet, or a decoy built from it,
exceeds `GLOBAL_MTU_SIZE`, final egress transport-segments it again into
MTU-sized segments with continuous sequence numbers.

A sequence gap, an out-of-order or retransmitted segment, exceeding the packet
or record limits, the capture timeout, or a same-flow packet arriving on another
worker releases the held segments unchanged and in order.

IPv4 fragments, including an `MF=1` first fragment and any nonzero-offset later
fragment, never enter First-SNI capture and continue on the normal fail-open
packet path.

#### When first-sni does nothing

The trick fails open, forwarding traffic unchanged, when:

- the packet is not IPv4, not TCP, or is an IPv4 fragment
- the payload is not, and does not begin, a TLS ClientHello record, or the
  ClientHello spans more than one TLS record, or its handshake length does not
  match the record body
- the ClientHello has no `server_name` extension or no `host_name` entry
- the ClientHello carries a TLS 1.3 `pre_shared_key` extension with PSK binders
  and the configured value would actually change the SNI bytes. `IpManipulator`
  does not own the PSK secret needed to recompute valid binders, so it skips
  crafting and leaves the original packet path alone
- the substitution would overflow a 16-bit TLS length field, the 24-bit
  handshake length, or the IPv4 total length, or would produce a non-positive
  length. The reason is logged and the original packet is forwarded
- no packet buffer is available for the copy

Capture slots are shared per tunnel, 16 per worker. When all of them are busy,
the oldest capture is abandoned and its held segments are released unchanged.

#### How first-sni differs from the other SNI tricks

- `sni-blender` fragments the real ClientHello at the IPv4 layer and invents no
  host name. `first-sni` adds a whole extra packet and leaves the real one
  intact.
- `smuggle-sni` sends the real ClientHello out through a separate helper branch
  and puts the crafted copy on the normal path. `first-sni` sends both copies on
  the normal path, decoy first.
- `overlap-sni` builds a multi-packet transcript with a fake `SYN` and two
  versions of one sequence range. `synfin-sni` additionally uses a synthetic
  `FIN`/`RST` and TLS-looking filler. `first-sni` emits no synthetic control
  packets and never splits the real ClientHello.
- `ech-sni-trick` reorders bytes that already exist inside the real ClientHello,
  whose decoy hello was embedded earlier by `TlsClient`; `IpManipulator` writes
  no host name of its own there.

#### Limitations and side effects

- Apart from the host name and its length fields, the decoy is byte identical to
  the real ClientHello, including the IPv4 identification and the TLS `random`
  and session id. A device that correlates ClientHello contents can recognize
  the pair.
- No padding extension is adjusted, so a configured name of a different length
  produces a decoy of a different size than the real packet.
- Each configured copy re-sends the full ClientHello payload, and a long
  configured name can push a copy past the MTU and cause extra transport
  segmentation at egress.
- The trick shapes only the client's ClientHello. It does nothing for DNS,
  address-based filtering, or anything the server sends.
- All packets of one flow must stay on one worker; otherwise the trick fails
  open for that flow with a warning.

### smuggle-sni

`smuggle-sni` creates a path-dependent split view of one TLS ClientHello. After
capturing the real ClientHello, it sends the client's original TCP segments on
`real-sni-upstream-node`. It sends a separately generated, equal-length
ClientHello carrying the configured host name on the normal `next` branch. The
two views occupy the same TCP sequence ranges, but they are routed to different
branch entries rather than deliberately sent as an ordered overlap on one
branch.

The intended topology lets an inspection device on the normal branch parse the
generated SNI while the destination receives the real ClientHello through the
helper branch. The technique does not itself ensure that separation. If the
branches converge at the wrong point, packets are reordered, or the destination
accepts the generated view, the connection can fail.

#### Which flow and ClientHello are selected

Smuggle-SNI operates only on whole, non-fragmented IPv4 TCP packets and creates
a flow record only after seeing a payload-free opening `SYN`. The accepted
opener has `SYN` plus an optional combination of `ECE` and `CWR`; `ACK`, `FIN`,
`RST`, `PSH`, `URG`, any other flag, or TCP Fast Open payload makes it
ineligible. If this node did not observe that opener, later packets on the tuple
pass without Smuggle-SNI processing.

The first two upstream packets in a tracked flow pass normally and count as
warmup. Normally they are the opening `SYN` and the client's final handshake
`ACK`; the downstream `SYN|ACK` is not counted. Capture begins with the next
upstream packet. This ordinal rule means a ClientHello sent in the second
upstream packet is not transformed on that transmission; only a later eligible
copy, such as a retransmission after warmup, could become the capture candidate.

At the capture point, the TCP payload must begin a TLS handshake record whose
handshake is a ClientHello with a usable first `host_name` SNI entry. A complete
one-segment record is accepted immediately. An incomplete record is retained
while exact contiguous continuations are collected. The starting segment must
contain at least the first nine TLS bytes so the record and ClientHello lengths
are known; a shorter prefix does not start capture.

- every continuation must have nonzero payload and sequence
  `previous.seq + previous.payload_len`, using normal 32-bit TCP sequence
  arithmetic
- the complete capture may use at most 16 TCP packets
- the complete TLS record, including its five-byte record header, may be at
  most 16,384 bytes
- the ClientHello handshake must exactly fill that one TLS record; a
  ClientHello split across TLS records or followed by another handshake message
  in the same record is unsupported
- capture expires 1500 ms after the last captured fragment if no valid
  continuation advances it

An ACK-only packet, retransmission, gap, overlap, or out-of-order continuation
does not get merged into an active capture. It ends the attempt and releases
the retained packets followed by the current packet on the normal path. IPv4
fragments and unparseable packets bypass this capture and can overtake held
segments; the capture remains pending until a valid continuation or timeout.

Smuggle-SNI also has a speculative prestart queue for packet reordering. If the
first capture candidate has nonzero payload of at least 128 bytes, has no
recognizable ClientHello prefix, and is not an explicitly unsupported TLS
layout, it can be held until 50 ms after the last speculative update in case an
earlier-sequence ClientHello start arrives afterward. Up to 16 distinct
sequence-numbered packets can be retained. Once a start arrives, only packets
that form the exact next sequence are drained into the ClientHello capture;
unrelated remainder packets are released normally. Timeout, duplicate sequence,
capacity pressure, or replacement of the speculative slot releases the held
packets unchanged and makes that flow passthrough. A short non-TLS packet or an
ACK-only candidate is not speculatively held and selects passthrough
immediately. The prestart queue has no separate byte cap beyond its 16-packet
bound and the size of each IPv4 packet.

Capture and prestart slots come from tunnel-wide pools sized at 16 of each per
configured worker and shared with the other tricks that use TLS capture. If a
pool is full, its oldest active slot is released unchanged to admit the new
capture. All fragments of a capture must stay on one WaterWall worker. A
cross-worker continuation fails open: each retained packet is returned through
its owner worker, but original global arrival order cannot be guaranteed.

#### How the two ClientHello views are built

Let the real ClientHello TLS record have length `R`, including its five-byte TLS
record header. Let captured TCP packets `P0 ... Pn` carry contiguous payload
lengths `L0 ... Ln`, beginning at TCP sequence `S`. The final captured packet
may also contain bytes after the end of the ClientHello record, so
`L0 + ... + Ln` can be greater than `R`.

After capture, the internal `TlsClient` creates a complete new ClientHello with
the configured `smuggle-sni`. This is not an in-place SNI edit or a clone of the
client's fingerprint. The generated record uses the internal client's TLS
randomness, extensions, key share, default ALPN order `h2`, `http/1.1`, and has
`x25519mlkem768` disabled. It must parse as exactly one ClientHello record, must
contain the configured host name, and its complete length `G` must satisfy
`G = R`. Changing the configured host can change `G` and therefore whether the
equality succeeds, although generated padding and extension choices mean the
length relationship is not necessarily one-for-one.

For every captured packet `Pi`, `IpManipulator` makes one normal-branch packet
`Fi` by copying the entire original IPv4/TCP packet and replacing only the
portion of its TCP payload that intersects the first `R` stream bytes with the
corresponding generated bytes. Therefore, before final egress processing:

- `Fi` has the same source and destination addresses and ports, TCP sequence and
  acknowledgement numbers, payload length, TCP flags, window and options, IPv4
  identification and TTL, and packet boundary as `Pi`
- concatenating the first `R` payload bytes of `F0 ... Fn` yields the generated
  ClientHello exactly
- payload bytes after the real ClientHello record are copied unchanged from the
  original packet
- checksums are recalculated because the TLS payload changed

The original `P0 ... Pn` packets are then sent, in reconstructed sequence order,
through `real-sni-upstream-node`. That helper send preserves the original tuple
and does not apply this node's port-ghost trailer. The generated `F0 ... Fn`
batch uses the normal `next` branch, where compatible final protocol swap,
port-ghost, checksum, and MTU handling can still run. Final MTU shaping may split
an oversized packet, so the captured boundaries are preserved only up to that
egress stage.

The helper originals and normal generated batch bypass the remaining
Smuggle-SNI/stateful-SNI pipeline rather than being inspected again. Same-node
packet duplication, SNI Blender, other stateful SNI tricks, and upstream TCP-bit
rewrites are configuration-incompatible with Smuggle-SNI. Protocol swap, port
ghost, downstream-only TCP-bit actions, and Smuggle-FIN may coexist subject to
their own behavior; the real helper packets still use the tuple-preserving path
described above.

#### Branch order, delay, and the 50-second barrier

The first captured segment may already have waited for the remainder of the
ClientHello. Once capture and generation succeed, the observable transcript is:

```text
t0:        send real P0 ... Pn to real-sni-upstream-node
t0 + D:    send generated F0 ... Fn to normal next
t0 + W:    release later queued upstream packets to normal next

D = smuggle-sni-delay-ms
W = max(50000, D + 1) milliseconds
```

All real packets are submitted to the helper before the fake batch becomes
eligible. At `D = 0`, the complete fake batch is emitted synchronously after the
real batch. There is no pacing between segments inside either batch. Branches
can have different latency, however, so this submission order is not a guarantee
of arrival order after they traverse the network.

The `D` setting delays only the generated batch. It does not set the release
time for later client traffic. A separate ordering barrier remains open until
`t0 + W`; this is 50 seconds for every delay through 49,999 ms, including zero,
and one millisecond after the fake due time for larger delays. Parseable
same-flow upstream packets arriving during that window—including ACKs,
retransmissions, application data, and `FIN`/`RST`—enter a FIFO behind the
complete generated batch. Downstream packets are never put in this barrier.
Unparseable packets, IPv4 fragments, and unrelated flows bypass it and can
overtake retained traffic.

The follow-on FIFO holds at most 16 packets and 256 KiB. If it reaches either
limit, a packet arrives on a different worker, the deadline is already past, or
a timer cannot be scheduled, the barrier fails open: any unsent generated
packets leave first, then the retained FIFO, then the current packet. This
preserves per-owner-worker order but can send the generated transcript earlier
than configured. A queued upstream `FIN` or `RST` remains behind earlier data
and removes the flow record after release.

Speculative prestart packets that are not incorporated into the contiguous
ClientHello are outside this post-success barrier. They are released through the
normal path when prestart processing finishes and, in reordering cases, can
appear before the generated batch.

#### What each participant may see

- **Client:** sends only the real ClientHello segments. WaterWall suppresses
  those segments from the normal branch, sends them through the helper, and can
  hold later client packets for the ordering window. The added capture and
  barrier delays can trigger TCP retransmissions, RTO backoff, congestion-window
  changes, or an application-visible stall.
- **Normal-path middlebox:** is intended to reconstruct the generated record at
  the client's real sequence numbers and parse the configured SNI. Because its
  segment sizes, flags, acknowledgement values, and general header shape are
  copied from the client packets, the TCP envelope resembles the captured flow,
  although the TLS fingerprint and cryptographic contents come from WaterWall's
  internal `TlsClient`.
- **Helper-path device or destination:** receives the original ClientHello
  segments after capture completes. If the helper route reaches the destination
  while the generated packets are kept from it, the server sees the client's
  real TLS random, extensions, key share, SNI, and transcript. Equal record
  lengths keep subsequent TCP sequence numbers aligned when traffic later uses
  the normal path again.

If the destination receives only the generated ClientHello, its ServerHello and
key schedule correspond to WaterWall's independent ClientHello, not to the
client's TLS state, so the client will generally be unable to continue the
handshake. If it receives both views, they are conflicting bytes on identical
sequence ranges; first-arrival/last-arrival reassembly, loss, retransmission,
normalization, and path ordering determine which view survives. The real batch
is submitted first, but that does not make server-side first-arrival behavior
safe across separate branches.

The trick therefore depends on topology: the observer intended to see the fake
must be on the normal branch, the endpoint intended to complete TLS must see the
real branch view, and later traffic and responses must rejoin coherently. NAT,
firewall state, asymmetric routing, anti-spoofing, TCP normalization, and
different MTUs on the two branches can all defeat that arrangement.

#### Fail-open behavior, closes, and flow lifetime

Before any real packet is sent to the helper, the attempt fails open to the
normal branch when the flow opener was not observed or its table record cannot
be admitted, the capture candidate is unsupported, the record is malformed or
lacks SNI, sequence continuity or worker affinity is lost, a capture/prestart
timeout or limit is reached, memory or timer setup fails, or the generated
record is invalid or has a length other than `R`. Retained originals are
forwarded unchanged by Smuggle-SNI through normal egress. On same-worker paths
they are released in capture order; cross-worker recovery cannot promise global
wire order.

If the real ClientHello contains a TLS 1.3 `pre_shared_key` extension with PSK
binders and the configured SNI differs from the real SNI, Smuggle-SNI also fails
open. WaterWall does not have the resumption secret needed to recompute binders
for an altered ClientHello. The source applies this guard only when the SNI
would change; an equal configured SNI is not rejected by this condition, though
all other generated-record validation and equal-length requirements still
apply.

Once the helper originals have been sent, a delay-scheduler failure cannot undo
that branch transmission. It instead releases the generated batch immediately
on the normal branch. Tunnel or flow-table destruction disposes of still-held
capture, fake, and FIFO buffers rather than forwarding them during teardown.

An upstream `FIN` or `RST` during prestart or ClientHello capture flushes held
originals to the normal path and removes the flow. On the normal same-worker
path, those held packets are submitted before the close; cross-worker recovery
cannot guarantee global order. During the post-success barrier, the close is
queued behind earlier upstream traffic. A downstream `FIN` or `RST` is never
delayed; it flushes an unfinished capture but removes a post-success flow
immediately, which disposes of any still-delayed generated or follow-on upstream
packets. Other downstream traffic is unchanged. A lightweight downstream hook
can log a ServerHello that begins in one whole TCP payload, but it does not
validate the branch outcome or alter the packet.

Downstream TCP-bit rewrites are allowed in the same node and run before that
logging/close hook. Consequently, adding or removing `FIN`/`RST` with a
`dw-tcp-bit-*` setting also changes whether Smuggle-SNI observes a downstream
close and performs this cleanup.

For an admitted tracked flow, either success or ordinary fail-open leaves the
normalized four-tuple in passthrough state and Smuggle-SNI does not retry.
Activity can retain that record for up to 20 minutes of idle time. A valid new
opening `SYN` starts a new generation; it discards any old capture/prestart
packets and destroys an old delay barrier rather than replaying those stale
bytes. An upstream or downstream `FIN`/`RST` normally removes the record as
described above.

#### How smuggle-sni differs from the other tricks

- `first-sni` edits the real ClientHello's SNI and length fields in extra copies
  and sends both decoy and original on the normal branch. Smuggle-SNI generates
  the whole alternate record, requires equal record length, and routes the real
  packets through a helper.
- `overlap-sni` and `synfin-sni` emit conflicting sequence ranges and synthetic
  TCP control packets on the normal branch. Smuggle-SNI uses no fake `SYN`,
  `FIN`, or `RST`; its split view comes from branch routing.
- `ech-sni-trick` extracts a byte-identical decoy already embedded by
  `TlsClient` and sends it out of order. Smuggle-SNI creates a new conventional
  ClientHello from its configured host name.
- `sni-blender` fragments and shuffles the real packet at IPv4 without creating
  another TLS transcript. `smuggle-fin` does not inspect TLS at all and routes a
  synthetic reverse `FIN|ACK` while holding normal traffic.

### overlap-sni

This trick is driven by client-to-server IPv4 TCP packets. It replaces two real
ClientHello segments with a crafted transcript on the normal upstream path. The
downstream path does not rewrite packets; it only observes `FIN`/`RST` to clean
up the corresponding flow.

#### What the trick is for

`overlap-sni` makes one TCP sequence range ambiguous. It sends the real beginning
of the client's ClientHello, then a fake TCP `SYN`, then a generated ClientHello
with a different host name on exactly the same sequence numbers, and finally the
rest of the real ClientHello.

Where `first-sni` relies on a decoy packet being seen first, `overlap-sni`
targets TCP reassembly. The intended split view is that the destination keeps the
first-arriving real bytes for the overlapping range, while an intermediate
device treats the fake `SYN` as a new flow or replaces earlier bytes with the
later overlap and parses the generated host name. TCP overlap handling and
middlebox state machines vary, so neither view is guaranteed.

This is one of the most invasive tricks in the node. It changes the client's
segment boundaries, injects a non-handshake `SYN` into an established flow,
delays subsequent upstream traffic, and deliberately blocks some ClientHello
layouts.

#### Which flow and packets are selected

A flow record is created only by a payload-free opening `SYN` (`SYN`, optionally
with ECN `ECE`/`CWR`, but no `ACK`, `FIN`, `RST`, or payload). TCP Fast Open SYN
data is therefore not eligible. Traffic on a 4-tuple whose opening `SYN` this
node did not see passes unchanged. A later opening `SYN` on the same tuple starts
a new flow generation.

1. Warmup: the first two upstream packets of the flow pass unchanged. In a normal
   connection these are the `SYN` itself and the client's handshake-completing
   `ACK`, so the decision point is the third upstream packet, that is, the
   client's first data segment.
2. Decision: the third packet is inspected. A payload-free packet, a payload that
   is not a TLS ClientHello, and a complete ClientHello record all move the flow
   straight to passthrough and are forwarded unchanged. Only a payload that
   begins a ClientHello record without completing it is held. Any extra
   payload-free packet before the ClientHello therefore consumes the decision
   slot and disables the trick for that flow.
3. Hold: the segment is retained inside `IpManipulator` and nothing is sent. A
   timer armed at `overlap-sni-hold-timeout-ms` releases it unchanged if the flow
   does not continue.
4. Pair: the very next upstream packet must carry nonzero payload beginning
   exactly at `held.seq + held.payload_len`. The two payloads must together
   contain a parseable ClientHello, including its host name, in one TLS record.
   On success they are replaced by the transcript below. An ACK-only packet,
   sequence gap, overlap/retransmission, still-incomplete record, ClientHello
   split across TLS records, or malformed SNI releases both packets unchanged
   and makes the flow passthrough. The trick waits for exactly one completion
   segment, not an arbitrary number of segments.

Because only an incomplete first ClientHello is held, this trick does nothing for
clients whose ClientHello fits in one TCP segment. Its packet-ordinal rule also
means an extra client packet between the handshake ACK and ClientHello can
disable it even when the ClientHello is split.

#### Successful wire transcript

The held segment and the completing segment are validated as strictly contiguous,
`current.seq == held.seq + held.payload_len` with nonzero payload on both, and
virtually reassembled into one combined payload. `IpManipulator` then generates
its own ClientHello for the configured `overlap-sni` value through an internal
`TlsClient` and parses the real host name out of the combined bytes.

Let:

- `S` be the held segment's first TCP sequence number
- `H` be its TCP payload length
- `R` be the two real payload lengths combined
- `G` be the complete generated ClientHello length
- `O` be the real host name's offset from the start of the combined TCP payload

A successful transcript requires `0 < G <= 900`, `G <= R`, and `O >= G`. At the
time the second real segment arrives, the normal upstream path emits or schedules:

1. Packet `Y` immediately: real bytes `[0, G)` at sequence `S`. It copies the
   held packet's IP/TCP headers and TCP flags. This is the real version of the
   overlapping range.
2. A fake `SYN` immediately after `Y`: a header-only packet on the same 4-tuple,
   with sequence `S - 1`, acknowledgement `0`, and only `SYN` set. It copies the
   held packet's remaining IPv4/TCP header fields, including its TCP header
   length, options, and window; only its length, sequence, acknowledgement,
   flags, identification, optional TTL, and checksums are changed.
3. Packet `X` after `overlap-sni-delay-ms`: the generated ClientHello, exactly
   `G` bytes at sequence `S`. It covers the same sequence interval as `Y` but
   contains the configured host name and the internal `TlsClient` fingerprint.
4. The real continuation at 2 ms intervals after `X`. If `G < H`, one packet
   carries real bytes `[G, H)` at `S + G`, followed by a packet containing the
   completing segment at its original sequence `S + H`. If `G >= H`, only the
   still-needed portion of the completing segment, real bytes `[G, R)`, is sent
   at `S + G`; its earlier bytes were already included in `Y`.

Every packet is emitted with recomputed checksums and its own incrementing IPv4
identification: `Y` uses the held packet's identification, then the fake `SYN`,
`X`, and any continuation packets increment it by one. `Y` and `X` use the held
packet's flags. When a held-segment continuation is followed by a completing-
segment continuation, the former keeps only `CWR`, `ECE`, `URG`, and `ACK`; the
last packet keeps the completing segment's flags. The original two packets are
recycled and never appear on the wire. The replacement therefore contains four
or five packets, depending on whether `G` reaches into the completing segment.

Local scheduling preserves that order, but the network can still drop or
reorder packets. `overlap-sni-delay-ms` is the only configurable separation;
the 2 ms continuation spacing is fixed.

#### What each participant sees

- The destination is intended to accept `Y` first and retain those real bytes.
  If the fake `SYN` reaches an established TCP endpoint, standards-oriented
  stacks commonly drop it and send a challenge or duplicate ACK, but other
  stacks, firewalls, and load balancers may reset or otherwise disturb the
  connection. If the connection remains established, a first-arrival-wins TCP
  receiver treats `X` as conflicting duplicate data for `[S, S + G)` and the
  continuation completes the real stream. Its TLS layer then receives the
  original ClientHello.
- A reassembling middlebox receives an incomplete real prefix in `Y`; the
  enforced `O >= G` condition keeps the real host name out of that prefix. If
  the fake `SYN` resets its flow state, `X` is then a complete ClientHello with
  the configured host name. A device that does not reset but prefers later bytes
  for an overlap can reach the same result. The subsequent real bytes start at
  or after the end of `X` and may be ignored once the device has classified the
  complete generated hello.
- The client did send the original two segments, but `IpManipulator` suppresses
  them and sends the replacement transcript on its behalf. The client can see
  duplicate/challenge ACKs or a reset caused by the fake `SYN`. If the server
  does not acknowledge the reconstructed real bytes, the client may retransmit
  its original ClientHello segments.

The desired split view depends on `Y` reaching the server before `X`, the fake
`SYN` not terminating server-side state, and the middlebox using a different
policy from the server. Loss, path reordering, TCP normalization, SYN proxies,
and devices that validate receive windows can all defeat the technique. In
particular, if `X` reaches the destination before `Y`, the destination may accept
the generated bytes instead of the real ones and the TLS connection will not
have the intended transcript.

#### Blocked flows

The implementation requires the complete generated hello to end no later than
the start of the real host name: `O >= G`. This keeps the real SNI wholly outside
the ambiguous range and in the later real continuation. If `O < G`, the trick
does not fall back to normal forwarding. It logs the real name and both offsets,
drops the held and current packets, and marks the flow blocked.

A blocked flow drops every later upstream packet. An upstream `FIN` or `RST`
removes the record but is itself dropped; a downstream `FIN` or `RST` is
forwarded unchanged and also removes the record. `IpManipulator` does not inject
a reset to tell the client why the data disappeared, so the usual visible result
is a stalled connection followed by a client timeout or a close initiated by
the server/path.

This is a deliberate fail-closed path rather than a fail-open one, and it is the
main risk of enabling `overlap-sni`. A longer configured name tends to increase
`G`; the real client's extension ordering and padding determine `O`. Many normal
ClientHellos place SNI too early for this condition, so representative packet
captures should be checked before deployment.

#### Delay window, retransmissions, and close packets

After a successful transcript the flow enters passthrough with a delay window of
`max(5000 ms, overlap-sni-delay-ms + 5 ms)`. While it is open, later upstream
packets of the flow, ACKs and `FIN`/`RST` included, enter the per-flow FIFO of at
most 16 packets and 256 KiB and are released together at the window deadline. The
scheduled transcript tail always leaves ahead of that FIFO. Downstream traffic is
never delayed.

This FIFO also catches TCP retransmissions sent after the crafted transcript has
been built. A retransmission or ACK-only packet arriving while the initial
segment is merely held instead fails the required two-packet pairing, releases
the held packet followed by the current packet unchanged, and makes the flow
passthrough.

FIFO overflow, a packet for the retained flow state arriving on another worker,
or a scheduling failure releases pending output in order rather than extending
the stall: the remaining crafted transcript goes first, followed by queued
packets and then the current packet. On a busy flow, the FIFO limit can therefore
end the nominal five-second window early.

The downstream path never changes packet bytes. A downstream `FIN` or `RST`
during the initial hold releases that held upstream segment unchanged and removes
the flow. During the post-transcript delay window it removes the flow and
cancels any still-scheduled crafted continuation and queued upstream packets;
the downstream close packet itself continues unchanged. An upstream `FIN` or
`RST` in the delay window remains ordered behind the crafted transcript and any
older queued packets.

#### When overlap-sni does nothing

The trick fails open, releasing any held segment and forwarding traffic
unchanged, when:

- the flow's opening `SYN` was never observed by this node
- the packet is not IPv4, not TCP, or is an IPv4 fragment
- the third packet has no payload, is not a TLS ClientHello, or already carries a
  complete ClientHello record
- the completing segment does not arrive within `overlap-sni-hold-timeout-ms`
- the very next packet is not sequence-contiguous with the held one, has no
  payload, or still does not complete a supported one-record ClientHello
- the combined bytes do not parse as a ClientHello with a host-name entry
- the internal `TlsClient` cannot generate a hello, the generated hello exceeds
  900 bytes, or it is longer than the real combined payload
- the replacement packets cannot be built, the hold timer cannot be armed, the
  flow table cannot admit the opening `SYN`, or retained state crosses workers

The `O < G` case described under "Blocked flows" is the intentional exception:
it fails closed and does not release the two selected real packets.

#### How overlap-sni differs from the other SNI tricks

- `first-sni` copies the client's own ClientHello, changes its host name, and
  sends the decoy before the untouched real packet. It can operate on a
  single-segment ClientHello and uses TTL or a random sequence number to keep the
  decoy away from the server; it does not inject a fake handshake `SYN`.
- `smuggle-sni` can capture up to 16 ClientHello segments, sends the real segments
  through an auxiliary branch, and later sends a generated copy on the normal
  branch while preserving the captured segmentation. `overlap-sni` accepts
  exactly two ClientHello segments and puts both views on the same normal path.
- `synfin-sni` also starts from a two-segment ClientHello but adds a crafted
  `FIN|ACK` or `RST|ACK`, a fake `SYN`, a generated hello, and TLS-looking filler
  in one immediate transcript. `overlap-sni` has no synthetic close or filler
  packet and instead relies on the exact `Y`/`X` overlap plus configurable delay.
- `sni-blender` fragments and reorders the real packet at the IPv4 layer without
  inventing another host name. `ech-sni-trick` reorders a fake inner ClientHello
  already embedded by `TlsClient`; it does not generate packet `X` here.

#### Limitations and side effects

- Only whole, non-fragmented IPv4 TCP packets are eligible. IPv6 and IPv4
  fragments pass unchanged.
- A normal top-level `next` is required. All crafted packets use that path; there
  is no overlap-specific helper branch.
- The generated hello follows the internal `TlsClient` fingerprint, including
  its default ALPN list, rather than the real client's fingerprint. Only the
  generated packet contains the configured name; the real ClientHello bytes are
  never rewritten.
- The client's two original segment boundaries and the completing segment's IPv4
  identification are not preserved. The replacement is four or five packets
  with copied headers, sequential IPv4 identifiers, valid recomputed checksums,
  and fixed 2 ms tail spacing.
- The fake `SYN` is a protocol violation on an established connection and may be
  normalized, challenged, dropped, or answered with a reset. A low
  `overlap-sni-syn-ttl` can keep it from the server, but cannot guarantee how a
  nearer device interprets it.
- Each flow's packets must remain on one WaterWall worker while a packet or delay
  barrier is retained. A worker mismatch logs a warning and fails open.
- Flow records expire after 20 minutes of inactivity and are bounded by
  `stateful-flow-limit`. Tuple reuse begins a new generation so an old timer
  cannot release data into the replacement flow.
- The trick cannot share one `IpManipulator` instance with another stateful SNI
  trick, `sni-blender`, `packet-duplicate`, or an upstream TCP-bit action. Use a
  separate node if another compatible packet-shaping stage is required.

### ech-sni-trick

`ech-sni-trick` changes only the client-to-server packet transcript. The
downstream path leaves packet bytes untouched and watches only for a TCP `FIN`
or `RST` that should cancel retained state.

#### What the trick is for

This trick targets inspection devices that parse a TLS record found in an
individual TCP segment, or that make an early classification from out-of-order
data before the missing lower sequence range arrives. It puts a complete decoy
ClientHello on the wire first, at a valid but future TCP sequence number. The
ordinary outer ClientHello follows later and remains the byte stream delivered
to a correct TCP/TLS endpoint.

Unlike an overlap trick, the early segment does not conflict with the eventual
stream. It is a copy of bytes that already occur at the same sequence interval
inside the outer ClientHello. A strict TCP reassembler therefore reconstructs
only the original outer ClientHello. The hoped-for different view exists only
at an observer that parses the early segment by itself or remembers its SNI
before reassembly completes. This behavior is path- and middlebox-dependent and
is not guaranteed.

#### How the decoy gets into the outer ClientHello

The feature has two coordinated parts:

1. `TlsClient.settings.ech-sni-trick` creates a separate, complete TLS
   ClientHello record whose SNI is the configured decoy name. It uses the
   configured `TlsClient` ALPN list in the same order and disables the
   `x25519mlkem768` key share for this decoy so that it remains smaller.
2. `TlsClient` places those raw record bytes, unencrypted, in the payload field
   of a GREASE `encrypted_client_hello` extension in the real outer
   ClientHello. The outer cleartext SNI remains `TlsClient.settings.sni`.
3. `IpManipulator` captures the outer ClientHello, locates that already-
   embedded record, and copies it into the early TCP segment. It never generates
   the decoy, rewrites either SNI, or removes bytes from the outer hello.

This is not standards-based ECH confidentiality. The extension has a GREASE ECH
shape, but its payload is recognizable ClientHello plaintext rather than valid
ECH ciphertext. The expected destination behavior is to continue with the
outer ClientHello when it has no matching ECH configuration, but servers,
proxies, and security devices are not universally tolerant of unusual GREASE
payloads.

#### Flow eligibility and ClientHello capture

The trick is sequence-aware rather than packet-ordinal-based:

1. A payload-free opening `SYN` creates the flow record. `ECE` and `CWR` may be
   present independently or together for ECN negotiation; `ACK`, `FIN`, `RST`,
   any other flag, or TCP Fast Open payload makes the packet ineligible as an
   opener. If this node did not see the opening `SYN`, later packets on that
   tuple pass unchanged.
2. Payload-free upstream packets, including the TCP handshake's final `ACK` and
   ACKs interleaved between ClientHello segments, pass immediately and do not
   consume a capture slot.
3. The first non-empty upstream payload must begin with a recognizable TLS
   handshake record and ClientHello prefix. A complete one-packet ClientHello
   can be used immediately. A recognizable partial prefix starts capture; an
   unrelated first payload makes this flow permanently pass through until a new
   opening `SYN` starts another generation.
4. Further data segments are retained only when each begins exactly at the next
   expected TCP sequence number. Capture stops when the declared first TLS
   record is complete. A ClientHello spread across multiple TLS records is not
   supported. If the completing TCP segment also contains bytes after that
   record, the whole original segment is retained and later replayed, although
   only the first record is inspected.

At most 16 original packets may participate, and the declared TLS record,
including its five-byte header, may not exceed 16,384 bytes. The capture has a
1,500 ms inactivity timeout, refreshed by accepted data or an exact
retransmission. An exact retransmission of a packet already retained is
discarded as a duplicate while capture continues. A gap, out-of-order segment,
partial or conflicting overlap, unsupported TLS layout, resource failure, size
or packet limit, timeout, or worker-affinity mismatch fails open: retained
originals are forwarded before the current packet, and the rest of that flow
passes normally.

After capture, `IpManipulator` requires all of the following:

- a parseable outer ClientHello with a usable first `host_name` SNI entry;
- a syntactically parseable outer-form `encrypted_client_hello` extension and
  its bounded payload field; and
- exactly one complete TLS ClientHello record anywhere in that payload whose
  first SNI host name equals the configured `ech-sni-trick` value byte for byte.

Nonmatching ClientHello candidates do not count. Two matching candidates are
ambiguous and fail open. No match, a malformed or truncated candidate, an outer
hello without SNI or ECH, and an `IpManipulator`/`TlsClient` setting mismatch
also fail open by releasing the originals without emitting the decoy segment.

#### Successful TCP transcript

Let:

- `S` be the first captured packet's TCP sequence number;
- `O` be the decoy ClientHello's byte offset from the beginning of the captured
  TCP payload; and
- `L` be the complete decoy ClientHello record length.

The decoy already occupies stream interval `[S + O, S + O + L)` inside the
outer ClientHello. On success, the wire order is:

1. All original ClientHello packets remain held. `IpManipulator` creates one
   packet with sequence `S + O` and payload equal to exactly those `L` embedded
   bytes. If the embedded record crossed original packet boundaries, this copy
   still coalesces it into one TCP segment.
2. That packet is sent immediately. It copies its IPv4 and TCP header template
   from the captured data segment covering offset `O`, including addresses,
   ports, acknowledgement number, window, TCP options, TTL, and IPv4
   identification. Its length and sequence number are adjusted, checksums are
   recomputed, and its flags preserve `CWR`, `ECE`, `URG`, and `ACK` from the
   template, add `PSH`, and omit `SYN`, `FIN`, and `RST`. Reusing the template's
   IPv4 identification means the decoy and one original can have the same ID.
3. After `data-shard-1-delay`, original packet 1 is released with its original
   payload boundary, sequence number, and TCP flags.
4. When there is more than one captured packet, `IpManipulator` waits the
   additional `data-shard-2-delay`, then releases original packets 2 through N
   consecutively in their captured order. There is no per-packet delay within
   this second group.

Thus the nominal send times are `T`, `T + delay1`, and
`T + delay1 + delay2`. A one-packet ClientHello uses only the first delay. With
both settings at `0`, callback order still puts the decoy first, but all packets
leave back to back.

The retained originals are not rewritten by this trick. Their payload bytes at
`[S + O, S + O + L)` are identical to the early copy, so the destination never
has to choose between conflicting overlap contents. Compatible final-egress
features in the same node, such as protocol swap or port ghost, still run after
this transcript is built and can change the on-wire wrapper or segment it as
documented in their own sections.

#### What the client, middlebox, and server may see

- The client sends one ordinary outer ClientHello and does not know that
  `IpManipulator` retained it and injected a copy of an internal byte range.
  The early higher-sequence segment may cause the destination to return a
  duplicate ACK for `S`, and, when SACK was negotiated, a SACK block covering
  the received future range. These responses can influence the client's loss
  recovery even though the injected bytes equal data it already submitted.
- A packet-oriented inspector sees a TCP payload beginning with a complete TLS
  ClientHello carrying the configured decoy SNI before it sees the lower-
  sequence outer hello. A device that parses out-of-order payloads or latches
  the first SNI may classify the flow from that decoy. A strict stream
  reassembler instead waits for the gap, reconstructs the original outer
  ClientHello, and can see the real outer SNI; a device that examines both may
  ignore, replace, or penalize the earlier verdict.
- The destination TCP stack may buffer the early segment as out-of-order data,
  acknowledge it with SACK, or discard it because of its receive-window or
  normalization policy. Once the originals fill the gap, a tolerant stack
  reconstructs the same outer ClientHello bytes that `TlsClient` generated. Its
  TLS endpoint is then expected to use the outer SNI and treat the unusable
  GREASE ECH offer compatibly. TCP normalizers, SYN proxies, TLS gateways, and
  ECH-aware servers may behave differently.

The delays provide time for an early middlebox decision; they do not force one.
Larger values also increase handshake latency and the duration of TCP
reordering. Values near a sender's retransmission or application timeout can
defeat the connection rather than improve the trick.

#### Retransmissions, later traffic, and connection close

After the decoy is emitted, only an exact retransmission of a still-pending
original segment—same sequence, payload length, and payload bytes—is swallowed.
An ACK-only packet, later application data, or a partial/ambiguous overlap is
forwarded immediately. Later data is not queued behind the two release timers,
so it can itself overtake the held ClientHello and add more out-of-order traffic.
Once an original has been released, its retransmissions are no longer swallowed.

Close handling preserves TCP ordering where a graceful upstream close still
makes sense:

- An upstream `FIN` during incomplete capture releases captured originals before
  the `FIN`. During delayed release it flushes every still-pending original
  before the `FIN`.
- An upstream `RST` during delayed release discards pending originals and then
  passes the reset. During incomplete capture, the held originals are released
  before the reset packet.
- A downstream `FIN` or `RST` passes unchanged but removes the flow record,
  disposes of an incomplete capture, and cancels any originals that have not yet
  been released.

Flow records are keyed by the TCP four-tuple and a connection generation. A new
valid opening `SYN` on a reused tuple invalidates the preceding capture and
release timers before starting the replacement flow, so stale ClientHello bytes
are not injected into it. After release, the record remains in passthrough until
it closes, is replaced, or expires after 20 minutes of inactivity.

#### How ech-sni-trick differs from the other SNI tricks

- `first-sni` makes one or more full copies of the client's outer ClientHello,
  rewrites the SNI in each copy, and uses TTL or a random sequence number to try
  to keep those conflicting decoys away from the server. `ech-sni-trick` uses
  one pre-embedded decoy at its real in-stream sequence interval, with no TTL or
  random-sequence option and no conflicting bytes.
- `smuggle-sni` sends the real ClientHello over a configured helper branch and a
  generated decoy over the normal branch after a delay. `ech-sni-trick` needs no
  helper branch and sends both views on the normal path.
- `overlap-sni` and `synfin-sni` replace captured segment boundaries with
  deliberately conflicting sequence ranges and inject fake `SYN` and close or
  filler packets. `ech-sni-trick` injects no TCP control packet and replays the
  original segmentation.
- `sni-blender` fragments and reorders the real ClientHello at the IPv4 layer.
  `ech-sni-trick` does not create IPv4 fragments; it sends one extra TCP data
  segment copied from the GREASE ECH payload.

#### Limitations and side effects

- Only whole, non-fragmented IPv4 TCP packets are eligible. IPv6 and IPv4
  fragments pass unchanged.
- A normal top-level `next` is required. `IpManipulator` must see the opening
  `SYN`, and the first non-empty client payload must begin the supported
  one-record ClientHello layout.
- The decoy plus copied IP/TCP headers must fit `GLOBAL_MTU_SIZE`. An oversized
  decoy fails open rather than being split by the ECH trick. A longer configured
  SNI can enlarge both the outer record and this packet.
- The flow table is bounded by `stateful-flow-limit`; an unadmitted flow passes
  unchanged. Incomplete TLS captures also use a finite shared slot pool. Under
  pressure, an older incomplete capture can be released and moved to
  passthrough.
- Every retained packet for a flow must remain on one WaterWall worker. A
  worker-affinity mismatch fails open; if the upstream packet source cannot
  preserve affinity, use one event worker as described in the stateful-flow
  guidance.
- The early packet duplicates the template packet's IPv4 identification and can
  trigger duplicate ACKs, SACKs, retransmission heuristics, traffic-normalizer
  rules, or anomaly detection. The delays also hold memory and postpone the TLS
  handshake.
- This is not real ECH and provides no SNI confidentiality: the real SNI is in
  the outer ClientHello and the decoy SNI is visible inside the GREASE payload.
- The trick cannot share one `IpManipulator` with another stateful SNI trick,
  `sni-blender`, `packet-duplicate`, or an upstream TCP-bit action. Compatible
  operations that must shape its emitted packets belong in a following
  `IpManipulator` node.

### synfin-sni

`synfin-sni` is an upstream-only, stateful TCP overlap trick for a TLS
ClientHello split across exactly two selected data segments. It suppresses those
two original packets and emits a replacement transcript containing real bytes,
a synthetic close, a fake `SYN`, a generated decoy ClientHello, optional filler,
and the remaining real bytes. Downstream packets are not inspected or modified
by this trick.

#### What the trick is for

The intended split view uses both TCP connection state and conflicting overlap
policy. A destination that retains the first bytes received for a sequence range
can reconstruct the real ClientHello. An intermediate device may instead treat
the close and following `SYN` as a flow boundary, or prefer the later bytes in an
overlap, and parse the generated ClientHello carrying `synfin-sni`.

This is more invasive than merely sending a decoy first. It deliberately places
two different payloads on the same TCP sequence interval and injects a close and
new `SYN` into an established four-tuple. Its result depends on receive-window
checks, checksum validation, TTL, overlap policy, TCP normalization, and how a
device associates packets with flow generations. No particular server or
middlebox view is guaranteed.

#### Which flow and packets are selected

1. A record is created only when this node sees a payload-free opening `SYN`.
   `ECE` and `CWR` may accompany `SYN`; `ACK`, `FIN`, `RST`, any other flag, or
   TCP Fast Open payload makes the opener ineligible. Packets on an untracked
   tuple pass unchanged.
2. The first two non-close upstream packets pass unchanged and count as warmup.
   Normally they are the opening `SYN` and the client's final handshake `ACK`;
   the downstream `SYN|ACK` is not counted. Therefore the third upstream packet
   is normally the first ClientHello segment.
3. If that third packet is payload-free, is not the beginning of a recognizable
   TLS ClientHello, or already contains the complete first TLS record, it passes
   immediately and the flow becomes passthrough. Only a partial or fragmented
   one-record ClientHello beginning is held.
4. The very next upstream packet must have nonzero payload and begin exactly at
   `held.seq + held.payload_len`. The combined bytes must contain a parseable
   ClientHello whose handshake exactly fills one TLS record and has a usable
   first `host_name` SNI entry. An ACK, exact retransmission, gap, overlap,
   out-of-order segment, still-incomplete record, or malformed layout releases
   the held packet followed by the current packet unchanged and selects
   passthrough. The trick never waits for a third data segment.

The declared first TLS record may not exceed 16,384 bytes. If the completing
segment contains bytes after that record, those bytes remain part of the real
combined payload and are preserved in the real continuation. The hold is bounded
by `synfin-sni-hold-timeout-ms`; timeout releases the retained segment unchanged
and makes the flow passthrough.

#### Successful TCP transcript

Let:

- `S` be the held segment's first TCP sequence number
- `H` be the held segment's payload length
- `R` be the two real payload lengths combined
- `G` be the generated decoy ClientHello record length
- `O` be the real SNI host name's offset from the beginning of the combined TCP
  payload
- `A` be the chosen additional range, after runtime clamping
- `Y = G + A` be the length of the deliberately overlapping interval

Generation succeeds only when `0 < G <= 900`, `G <= R`, and `O >= G`. `A` is
chosen inclusively from the configured range after both ends are clamped so that
`0 <= A <= min(R - G, O - G)`. Consequently `Y <= O`: packet `Y` can end exactly
before the first real SNI byte, but never contains a byte of the real host name.

The original held and completing packets are recycled. Before any later egress
segmentation, five through seven replacement packets are sent synchronously in
this order:

1. **Real packet Y** — real bytes `[0, Y)` at sequence `S`. It uses the held
   packet's IP/TCP header and exact TCP flags. Its payload can cross the original
   boundary at `H`, so it may coalesce bytes from both selected segments.
2. **Synthetic close** — a header-only `FIN|ACK`, or `RST|ACK` when
   `synfin-sni-use-rst` is true. Its default sequence is `S + Y`, immediately
   after packet Y. It copies the held packet's acknowledgement number, window,
   TCP options, addresses, and ports.
3. **Fake SYN** — a header-only packet with only `SYN` set, acknowledgement `0`,
   and default sequence `S - 1`. It normally uses the captured opening `SYN` as
   its header template, preserving the SYN-style TCP options and window. If that
   template copy was unavailable, it falls back to the held data packet's header
   shape.
4. **Fake packet X** — the complete generated ClientHello, length `G`, at
   sequence `S`. Its flags preserve `CWR`, `ECE`, `URG`, and `ACK` from the held
   segment and add `PSH`; `SYN`, `FIN`, and `RST` are omitted. Thus X conflicts
   byte-for-byte in sequence space with real packet Y over `[S, S + G)`.
5. **Optional fake filler** — when `A > 0`, one packet covers
   `[S + G, S + Y)`. For `A >= 5`, its payload is a complete TLS Application Data
   record header (`17 03 03`, length `A - 5`) followed by random bytes. For
   `A < 5`, all `A` bytes are random and cannot form that complete record header.
6. **One or two real tails** — real bytes `[Y, R)` complete the original stream.
   If `Y < H`, the remainder of the held segment is emitted first at `S + Y`,
   followed by the completing segment at `S + H`. Otherwise only the unused
   suffix of the completing segment is sent at `S + Y`.

Packet Y starts with the held packet's IPv4 identification. The close, fake
`SYN`, X, filler, and tails use consecutively increasing identifications; the
completing packet's original identification is not retained. Rebuilt packets
normally have valid IPv4/TCP checksums. A held-segment tail followed by a second
tail keeps only `CWR`, `ECE`, `URG`, and `ACK`; the final tail uses the completing
segment's flags.

There is no pacing between these outputs. The hold timeout controls only how long
the first data segment can wait for its pair. Compatible final-egress behavior,
such as port ghost, protocol swap, or MTU-driven TCP segmentation, runs after the
transcript is built and can change the final wrapper or increase the on-wire
packet count.

#### What the client, middlebox, and destination may see

- The client sent two ordinary ClientHello segments, but WaterWall replaces them
  on the wire. Synthetic control packets and conflicting data can elicit
  duplicate ACKs, challenge ACKs, SACK changes, or a reset. If acknowledgement
  progress does not match what the client's TCP stack sent, it may retransmit
  the original segment boundaries; those later retransmissions are not hidden.
- A stateful middlebox first sees a real prefix that ends before the real host
  name, followed by a close and another `SYN`. With default sequences, the new
  `SYN` at `S - 1` makes X at `S` look like the first data of a new flow. Such a
  device may parse the decoy SNI, followed by the optional TLS-looking filler.
  A device that ignores the controls but uses last-arrival-wins overlap can also
  reconstruct X. A strict first-arrival-wins reassembler instead retains Y.
- The destination is intended to retain real packet Y for `[S, S + Y)`, ignore
  X and filler as conflicting duplicates, and append the real tail, producing
  the original ClientHello. This requires Y to arrive first and the synthetic
  close and `SYN` not to terminate or reset destination-side state. A valid,
  in-window `FIN` at `S + Y` can close the receive stream exactly where the real
  tail begins; an accepted `RST` terminates the connection immediately.

TTL, checksum, and random-sequence settings are ways to try to make a nearby
observer process the controls or X while a farther endpoint expires or rejects
them. They are not selectors for a specific device. Some middleboxes validate
checksums and receive windows; some destinations or intervening equipment repair,
normalize, or discard unusual packets. With all defaults, the synthetic packets
have valid checksums, coherent sequences, and the captured TTL, so they will
normally be capable of reaching and affecting the destination.

#### Effect of the control settings

- `synfin-sni-syn-ttl`, `synfin-sni-fin-ttl`, and `synfin-sni-fake-ttl` are
  independent. The last applies only to X, not to filler. Lower values shorten
  the relevant packet's path; `0` is put literally in the IPv4 header and will
  normally be discarded before routing beyond the local link.
- Random SYN/close checksums make both IPv4 and TCP checksum fields arbitrary.
  A passive classifier might still inspect such a packet while a validating
  endpoint drops it, but a validating middlebox drops it too. These settings do
  not damage the data packets' checksums. A later egress operation that must
  rebuild a packet, such as port-ghost tailing or MTU segmentation, can repair
  an arbitrary checksum, so use a separate stage carefully when bad checksums
  are essential to the experiment.
- `synfin-sni-random-syn-sequence` moves only the SYN. X remains at `S`, so the
  otherwise coherent `SYN(S - 1) -> data(S)` relationship is lost. This may keep
  the SYN out of a destination window but can also prevent a sequence-aware
  middlebox from accepting X as new-flow data.
- `synfin-sni-random-fin-sequence` moves only the close. It can make the close
  less likely to be in-window at the destination but less credible to a
  sequence-aware observer. `synfin-sni-use-rst` changes the control semantics,
  not its default position: `RST|ACK` is generally more destructive if accepted
  and, unlike FIN, does not represent an orderly end consuming one sequence
  number.
- Increasing the additional range makes Y's first-arrival real coverage larger
  and adds the same amount of later fake filler. This can move the real tail and
  close farther into the ClientHello, but it can never cross the real SNI start.
  Runtime clamping can reduce even the configured minimum to fit the actual
  record.

#### Failure, retransmission, and flow lifetime

Most unsupported cases fail open. Timeout, an invalid pair, a still-incomplete or
malformed ClientHello, missing SNI, generation failure, `G > 900`, `G > R`, packet
allocation failure, table-admission failure, or worker-affinity mismatch releases
or forwards the available packets without the crafted transcript and makes the
flow passthrough. If the hold timer itself cannot be armed, the held segment is
released immediately.

There is one intentional fail-closed case. If the real host name starts before
the generated record ends (`O < G`), the trick logs the mismatch, drops both
selected real packets, and marks the upstream flow blocked. Every later upstream
packet is dropped. An upstream `FIN` or `RST` removes the record but is also
dropped. A new valid opening `SYN` on the tuple starts a replacement generation.
The usual symptom is a stalled connection, not an explicit locally generated
reset.

During the initial hold, an upstream `FIN` or `RST` releases the held data before
forwarding the close and removes the record. After success the flow immediately
enters passthrough: later ACKs, application data, original-segment
retransmissions, and closes are not queued behind the crafted sequence. An
upstream `FIN` or `RST` removes the passthrough record. Downstream traffic,
including downstream `FIN`/`RST`, passes without SynFIN inspection and does not
remove SynFIN state; otherwise-unused records expire after 20 minutes of
inactivity.

Every retained pair must remain on one WaterWall worker. A cross-worker
completion fails open; the current packet continues on its worker and the held
packet is returned to its owner worker, so cross-worker release cannot promise
the original wire order. A new opening `SYN` on a reused tuple invalidates old
timer generations and starts warmup again; if it replaces an active hold, the old
held buffer is disposed rather than injected into the new connection.

#### How synfin-sni differs from the other SNI tricks

- `first-sni` clones the real ClientHello, changes its host name, and tries to
  keep the decoy away from the server with TTL or a random sequence. It can work
  on one ClientHello segment and injects no connection-state controls.
- `smuggle-sni` captures up to 16 segments and sends the real originals through
  a helper branch while a generated hello uses the normal branch after a delay.
  SynFIN accepts exactly one held segment plus its immediate contiguous
  completion, uses no helper branch, and emits all views back to back.
- `overlap-sni` uses the same two-segment selection and real-Y/fake-X overlap,
  but it injects only a fake `SYN`, fixes the overlap length at `G`, and schedules
  X and real tails with delays. SynFIN adds a preceding `FIN|ACK`/`RST|ACK`, can
  enlarge the overlap with filler, offers checksum and sequence controls, and
  has no post-transcript delay window.
- `ech-sni-trick` sends an out-of-order, byte-identical copy of a decoy already
  embedded by `TlsClient`; it creates no conflicting TCP bytes or control
  packets. `sni-blender` fragments and shuffles the real packet at IPv4 rather
  than replacing TCP segmentation or generating another ClientHello.

#### Limitations and side effects

- Only whole, non-fragmented IPv4 TCP packets are eligible. IPv6, IPv4 fragments,
  and TCP Fast Open SYN data pass unchanged.
- The trick works only when the ClientHello begins on the third upstream packet
  and is incomplete there but parseable after exactly one contiguous data
  segment. A one-segment ClientHello is deliberately not transformed.
- The generated ClientHello uses the internal `TlsClient` fingerprint and
  default ALPN list rather than the client's fingerprint. Its SNI must be 1 to
  255 bytes, and the generated record, the real record's extension order, and
  real SNI offset must satisfy the `G`, `R`, and `O` constraints above.
- The original two packet boundaries and the completing packet's IPv4
  identification are discarded. Rebuilt large TCP packets may be segmented by
  final egress to respect `GLOBAL_MTU_SIZE`, further changing the nominal five-
  to-seven-packet transcript.
- Valid close or SYN packets on an established connection are protocol-invasive
  and can be normalized, challenged, rate-limited, or treated as an attack by
  hosts, firewalls, NATs, load balancers, SYN proxies, and intrusion systems.
- The bounded flow table uses `stateful-flow-limit` and requires flow affinity.
  Admission pressure fails open; active holds retain packet memory until paired,
  timed out, closed upstream, replaced, or destroyed.
- A normal top-level `next` is required. The trick cannot share one
  `IpManipulator` with another stateful SNI trick, `sni-blender`,
  `packet-duplicate`, or an upstream TCP-bit action. Put compatible later packet
  shaping in another node and account for its effect on TTL, checksums, tuple,
  segmentation, and packet order.

### smuggle-fin

`smuggle-fin` is a two-branch ordering trick. It holds an ordinary data packet
on the normal path, sends a plausible reverse-direction `FIN|ACK` through a
separate helper path, and waits for an exact copy of that FIN to return on the
downstream path. The intent is to let a stateful device on the helper path see a
connection-closing signal before the original data is released. Whether that
changes classification or connection state depends on the topology and the
device; the trick does not guarantee that any middlebox will echo, accept, or
act on the FIN.

Despite the name `fin-sni-delay-ms`, this trick does not parse TLS, a
ClientHello, or SNI. It can trigger on any whole, non-fragmented IPv4 TCP packet
that has `ACK`, has at least one byte of TCP payload, and has none of `SYN`,
`FIN`, or `RST`. Flags such as `PSH`, `ECE`, `CWR`, and `URG` do not disqualify
an otherwise eligible packet. IPv6, IPv4 fragments, non-TCP packets, ACK-only
packets, and TCP Fast Open SYN data pass without starting this trick.

#### Trigger packet and mirrored FIN

Let the triggering packet be:

```text
client A:a -> server B:b
SEQ = S, ACK = K, payload length = L
```

`IpManipulator` first retains that complete packet instead of forwarding it on
the normal `next` branch. It then copies the packet's IPv4 and TCP headers,
removes all TCP payload, swaps both IP addresses and both TCP ports, and emits:

```text
server B:b -> client A:a
SEQ = K, ACK = S + L, flags = FIN|ACK, payload length = 0
```

Sequence arithmetic is TCP's 32-bit sequence arithmetic. The trigger cannot
contain `SYN` or `FIN`, so only its payload length advances the acknowledgement.
The copied header retains such fields as the trigger's IPv4 identification and
TTL and its TCP header length, options, and window. IPv4 total length is reduced
to the header-only length, the flags and sequence fields are replaced as shown,
and valid IPv4/TCP checksums are requested for egress. No setting changes the
FIN's TTL, flags, sequence numbers, or acknowledgement number.

The reverse numbers are chosen to look plausible for the same live connection:
`K` is the next server sequence the client said it expected, while `S + L`
acknowledges all bytes in the held client packet. The client itself sent only
the original data packet; it did not send this FIN. If the helper path actually
delivers the spoofed reverse packet to the client and the client's TCP stack
accepts it as in-window, the FIN can half-close the receive direction, advance
the expected server sequence by one, provoke an ACK, or otherwise disrupt the
connection. That endpoint effect is possible, not required by the trick.

The crafted packet is sent immediately through `real-fin-upstream-node`. It
does not traverse this node's upstream TCP-bit, stateful-SNI, SNI Blender, packet
duplication, or port-ghost stages. Protocol swap and final checksum handling can
still apply. The original data packet remains queued for the normal path and,
when released, continues through those later configured stages in their usual
order.

#### Echo recognition and release timing

For echo-confirmed release, the helper topology must return the crafted FIN as
a downstream packet through this `IpManipulator`. After downstream protocol and
port-ghost restoration, a packet matches only when all of these are true:

- it is a whole, non-fragmented IPv4 TCP packet in direction `B:b -> A:a`
- it has zero TCP payload
- its sequence is exactly `K` and its acknowledgement is exactly `S + L`
- after ignoring only `ECE` and `CWR`, its flags are exactly `FIN|ACK`

IPv4 identification, TTL, TCP window, and TCP options are not compared. A
normal TCP response to a FIN is normally an `ACK` with different direction and
sequence semantics, so it is not the required echo. Any additional flag other
than `ECE` or `CWR` also prevents a match.

The first exact echo is consumed and never forwarded toward the client. Exact
duplicates received while release is pending are consumed too. On the first
match, `fin-sni-delay-ms` schedules release of the queue. The hard
`fin-pause-timeout-ms` timer started when the trigger was captured remains
active, however, so the effective sequence is:

```text
t0: trigger is queued; hard timeout starts; mirrored FIN is sent
te: exact echoed FIN is consumed, if one arrives
release: earlier of (te + fin-sni-delay-ms) and
         (t0 + fin-pause-timeout-ms)
```

Consequently, the pause timeout must exceed the expected helper round trip plus
the desired post-echo delay if the full delay is important. A delay of `0`
releases immediately on the owner worker. If no echo arrives, the hard timeout
still releases the flow. Failure to arm the initial hard timer releases the
queued trigger immediately before the helper FIN is sent; failure to arrange a
cross-worker post-echo release leaves the original hard timer as the fallback.
Timer callbacks are tied to the exact pause generation, so a stale callback
cannot release a newer use of the same tuple. Once release has completed, a
later packet matching the old FIN is ordinary downstream traffic and is no
longer consumed by Smuggle-FIN.

#### What is queued and how it is replayed

While the pause is active in the normal packet-chain orientation, every
parseable upstream packet on the forward tuple and every parseable downstream
packet on its reverse tuple is held, regardless of flags or payload. This
includes retransmitted data, ACKs, later application data, and real `FIN` or
`RST` packets. The trigger is the first queue entry; the exact synthetic-FIN
echo is the exception because it is consumed as the release signal. Unparseable
or fragmented packets bypass the queue and can therefore overtake held traffic.
Unrelated flows are never held behind this flow.

The queue holds at most 256 packets and has no separate byte limit. If a 257th
packet arrives, or the queue cannot grow, the existing batch is forcibly
released in queue order, the current packet follows normally, and the flow is
marked confirmed so it is not paused again. Timeout and other forced-release
paths have the same no-retry behavior.

One flow-owner worker maintains the queue. Reverse packets received on another
worker are copied to the owner worker before being queued. Replay order is the
order in which the owner worker accepted the entries, which need not equal a
single global wire-arrival order when multiple workers are involved. If a
cross-worker handoff cannot be created or submitted, that reverse packet passes
on its current worker while the pause remains active, so it can overtake the
queue. Only one flow may be paused by `smuggle-fin` on each worker at a time; a
new eligible packet for another flow on that worker passes normally.

Each queue entry remembers whether its checksum needed recalculation. On
release, entries are replayed one at a time in the saved mixed-direction order:

- upstream packets restart at the beginning of the upstream
  `IpManipulator` pipeline; the now-confirmed Smuggle-FIN record prevents
  reinjection, and later upstream tricks and normal egress run once
- downstream packets resume immediately after `smuggle-fin`, because protocol
  and port-ghost restoration already ran before they were queued; later
  downstream stages run once

Smuggle-FIN does not split, overlap, rewrite, or reorder bytes within the
original TCP packets. Its deliberate ordering change is temporal: the synthetic
reverse FIN leaves before the held original data, and unrelated or bypassed
traffic may pass during the pause. Holding both directions can add latency and
can trigger retransmission timers, delayed-ACK behavior, congestion-window or
receive-window changes, and application-visible stalls.

#### Expected views and why the trick may work

- **Client:** sends its original data normally and sees none of WaterWall's
  queueing directly. It may receive the spoofed FIN if the helper path routes it
  there; accepting that FIN can disturb or close the connection as described
  above. It can retransmit held data when the pause approaches its RTO.
- **Helper-path middlebox:** can see a server-to-client `FIN|ACK` with sequence
  and acknowledgement values derived from current client data before that data
  appears on the normal branch. A device that accepts this packet for its flow
  state may mark one direction closed, discard later packets, change its parser
  state, or produce the exact downstream echo used by WaterWall. Stateless
  devices and devices that validate a different path, window, checksum, or flow
  history may simply ignore it.
- **Destination server:** is normally intended to receive the original client
  data later through `next`, unchanged by Smuggle-FIN itself. The synthetic
  packet has the reverse tuple and uses the helper branch, but routing and branch
  design ultimately determine whether it reaches a real endpoint or server-side
  observer.

The technique therefore relies on a path-specific difference: an intermediate
device must treat the early plausible FIN as meaningful while the actual
end-to-end connection remains usable long enough for the delayed original data
to succeed. TCP normalization, asymmetric routing, NAT state, SYN/FIN proxies,
sequence-window validation, anti-spoofing, checksum offload or validation, and
endpoint behavior can invalidate that assumption.

#### Flow lifetime, interactions, and limitations

After an exact echo or any forced release, the normalized four-tuple remains
confirmed and bypasses further Smuggle-FIN injection. Activity keeps a confirmed
record for up to 20 minutes of idle time. A same-orientation `SYN`, `FIN`, or
`RST` does not explicitly reset that record, so rapid reuse of exactly the same
tuple can continue to bypass the trick until it expires. In unusual chains where
an eligible reverse-oriented data packet is delivered through the upstream
callback, the sole canonical record can be reoriented; an active old queue is
then discarded rather than replayed.

Because the exact echo is identified only by tuple, flags, payload length,
sequence, and acknowledgement, a legitimate server `FIN|ACK` that happens to
match all those fields is indistinguishable and will be consumed. Conversely,
minor helper changes to sequence numbers or flags prevent confirmation and make
the flow wait for the hard timeout. Tunnel shutdown disposes of retained packets
rather than forwarding them during teardown.

`stateful-flow-limit` bounds the Smuggle-FIN table independently of the other
stateful tables. Admission pressure fails open, leaving the candidate packet on
the normal path without sending a mirrored FIN. The helper branch and normal
`next` must be distinct and must preserve a topology in which an exact echo can
return downstream. Flow-affinity changes are tolerated specially for reverse
packets through owner-worker handoff, but introduce the ordering qualifications
above.

Unlike the TLS/SNI tricks, `smuggle-fin` neither locates nor changes a
ClientHello. Unlike `smuggle-sni`, it sends a newly constructed header-only FIN
through the helper branch and withholds the original data; `smuggle-sni` sends
captured real ClientHello packets through its helper. Unlike `synfin-sni`, it
does not generate a TLS record, fake `SYN`, same-direction close, or overlapping
TCP sequence ranges. Unlike packet duplication, its helper packet has the
reverse tuple, different flags and sequence fields, no payload, and a different
release schedule.

It may be configured alongside a stateful SNI trick, SNI Blender, TCP-bit
rewrites, port ghost, protocol swap, or packet duplication when their own
compatibility rules permit it. This does not mean the stages operate on the
synthetic FIN: the helper FIN follows the bypass path described above, whereas
the released original packets enter the ordinary pipeline. The added pause and
replay timing can still change how those later stateful tricks classify a flow.
Final MTU shaping may segment a released oversized TCP data packet even though
Smuggle-FIN itself did not split it.

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
barrier, or held-packet group. Most stateful SNI holds fail open when a needed
same-tuple packet arrives on another worker. Smuggle-FIN is the exception for
reverse traffic during its pause: it copies that packet to the flow-owner worker
and queues it there, subject to the ordering and handoff limitations in the
dedicated section. This distinction matters only when an upstream producer does
not preserve shared flow affinity. `StreamToPackets` does preserve it by
re-affinitizing each decoded packet from its inner tuple before forwarding it.

- the canonical key normalizes the two endpoints, so a forward packet and its
  reverse select the same hash, the same shard and the same record
- the shard count follows the worker count, capped at 64, and the configured
  `stateful-flow-limit` is partitioned across shards so the shard limits sum to
  it exactly
- lookup is average O(1) through hash buckets and idle expiry pops a per-shard
  deadline heap, so no packet callback scans the whole table
- each table uses a CSPRNG-generated per-tunnel hash seed, keeping bucket
  selection unpredictable from observed tuples
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
registry is written and cleared by the flow-owner worker and is validated
against the table before use. Exact echoes and reverse packets may arrive on
another worker, but release and queue replay are returned to the owner.

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
- dedicated real-SNI and mirrored-FIN helper branches preserve their original
  tuples and do not receive a port-ghost trailer

## Notes And Caveats

- This tunnel is for raw packet chains, not normal byte-stream chains.
- The node advertises `kNodeLayer3`; its previous and next neighbor constraints
  remain `kNodeLayerAnything` for flexible packet-chain composition.
- Only IPv4 packets are modified by the current implementation.
- `first-sni` is upstream-only, rewrites the first TLS host-name entry in the crafted copy, and immediately fails open on traffic without a recognizable ClientHello start.
- `smuggle-sni` sends captured real ClientHello segments to
  `real-sni-upstream-node`, emits an equal-length generated ClientHello on the
  normal `next` branch after `smuggle-sni-delay-ms`, and holds later upstream
  traffic behind its separate ordering deadline.
- `overlap-sni` needs the flow's opening `SYN` and an incomplete first
  ClientHello segment; anything else passes through. When the real host name
  begins before the generated hello ends, it blocks the flow on purpose and
  drops its later upstream packets instead of failing open.
- `smuggle-fin` starts upstream and injects a crafted mirrored FIN/ACK packet to
  `real-fin-upstream-node`, then queues both flow directions on the owner worker
  until the expected downstream echo plus optional `fin-sni-delay-ms` completes
  or the hard `fin-pause-timeout-ms` releases them.
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
- Unless `first-sni-ttl` or `first-sni-random-tcp-sequence` keeps the decoy away
  from the destination, the decoy ClientHello reaches the server as in-window
  data ahead of the real one and normally breaks the TLS handshake.
- The struct contains `trick_sni_blender_packets_delay_max`, but current JSON parsing does not expose or use it.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` |
| `layer_group_prev_node` | `kNodeLayerAnything` |
| `layer_group_next_node` | `kNodeLayerAnything` |
| `required_padding_left` | `0` bytes |
