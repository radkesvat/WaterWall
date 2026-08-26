<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/PacketsToConnection.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/PacketsToConnection.mdx, and all files must keep the same documentation version.
-->

# PacketsToConnection

`PacketsToConnection` is a packet-to-transport bridge built on lwIP.

It accepts raw IPv4 packets on the packet side, injects them into lwIP, and exposes the resulting transport flows as normal Waterwall `line_t` connections toward the next tunnel.

## What It Is

This node is for chains that start from packet traffic and then want to enter Waterwall's normal connection-oriented world.

Conceptually:

- packet side -> `PacketsToConnection` -> normal Waterwall service chain
- service-chain responses -> `PacketsToConnection` -> raw IP packets back to the packet side

It is closer to a small in-process transport stack bridge than to a framing adapter.

## What It Is Not

- It is not a TUN device manager.
- It does not create or configure routes or OS policy rules.
- It does not replace `TunDevice`.
- It does not serialize packets onto a stream like `PacketsToStream`.

`TunDevice` owns the real packet adapter side.

`PacketsToConnection` owns the lwIP transport bridge side.

## Current Protocol Support

- IPv4: supported
- TCP: supported
- UDP: supported as per-flow Waterwall lines
- IPv6: not supported
- ICMP: not supported

Unsupported packets are dropped conservatively.

## Checksum Finalization Boundary

`PacketsToConnection` is the final consumer of the packet line's one-packet checksum recalculation request. It takes
and clears that request before any validation or drop path, normalizes shifted input into mutable aligned storage, and
then repairs the supported checksums before typed parsing or lwIP ingress. A malformed, IPv6, stopping, or refused
packet therefore cannot leak its request into the next unrelated packet on the worker line.

For an unfragmented IPv4 TCP or UDP packet, finalization repairs the IPv4 header and transport checksum. For an IPv4
fragment, only the IPv4 header checksum can be repaired from that fragment; the node never invents a whole-datagram
TCP or UDP checksum from incomplete transport bytes.

## Flow Model

### Packet ingress

Upstream payload must be a full IPv4 packet.

`PacketsToConnection` does not create one lwIP `netif` per destination IP.

Instead, it keeps a worker-local route context for each packet worker that sends packets into the tunnel. For IPv4, that route context owns one lwIP `netif` with `NETIF_FLAG_PRETEND` enabled.

The destination IP is preserved in the packet and in the lwIP PCB tuple, but it is not used as the key for creating separate route contexts. In the current source, the IPv4 route-context lookup is keyed by packet worker id.

For each worker-local pretend netif:

- TCP gets one pretend wildcard listener on first TCP packet
- UDP gets one pretend wildcard PCB on first UDP packet

The Waterwall lwIP pretend patch lets those wildcard PCBs accept packets for arbitrary destination addresses and ports on the pretend netif while still preserving the original local destination tuple.

### TCP flow creation

When lwIP accepts a TCP connection:

- `PacketsToConnection` creates a real Waterwall line
- fills the line source/destination address context from the TCP tuple
- schedules upstream `Init`
- forwards later payload with upstream `Payload`

Downstream payload from the next tunnel is written back into lwIP with `tcp_write()`.

The TCP listener is not per destination port. It is bound as a pretend listener on the worker-local netif, and accepted TCP PCBs carry the original destination IP and port from the packet.

### UDP flow creation

UDP is tracked per worker-local route context and per 4-tuple:

- source IPv4 address
- destination IPv4 address
- source port
- destination port

When the first datagram for a UDP flow arrives:

- `PacketsToConnection` creates a real Waterwall line for that flow
- fills source/destination address context
- schedules a checked owner-worker Open operation that sends upstream `Init` and arms the one idle timer
- forwards datagrams with upstream `Payload`

Open is required control and is queued before the intentionally lossy payload operation. If Open admission is refused,
the node first detaches the PCB, timer, and flow-map entry under the lwIP core lock, records the owned line in its
preallocated terminal-reconciliation registry, and then requests orderly shutdown as escalation. Cleanup therefore does
not depend on the refused queue or on Stop discovering a still-registered flow. A later payload refusal is still an
ordinary UDP drop because the timer already bounds the flow.

Downstream payload from the next tunnel is sent back through the connected UDP PCB, using the original local destination address and port as the packet source.

UDP lines are closed by idle timeout, not by packet half-close semantics.

Like TCP, the initial UDP listener is not per destination port. The pretend UDP path creates or reuses a connected per-flow UDP PCB carrying the original source and destination tuple, and `PacketsToConnection` maps that tuple to a Waterwall line.

## Worker And Lifetime Model

This tunnel sits on a shared packet line on the packet side and creates normal Waterwall lines behind it.

Important internal rules:

- the packet line is not closed during runtime
- packet-line `Init` is a startup/bootstrap event, not a per-flow open
- generated TCP/UDP Waterwall lines are owned by the packet worker that accepted the flow
- lwIP callbacks hand work back to the owning line worker through the typed-result `lineScheduleTask()` and
  `lineScheduleTaskWithBuf()` contract. Required control refusal makes the producer terminal while the lwIP core lock
  still protects its registry; optional cancellation is deliberately null so cleanup cannot re-enter that lock.
  Buffered delivery transfers its copied buffer on every result
- UDP idle close uses one cancellable owner-worker timer. The timer owns exactly one line reference while armed,
  activity resets the same timer, and close cancels it and drops the reference before line state is zeroed
- packets emitted back to the packet side use the worker packet line for that packet worker
- the worker-local netifs inherit the core `misc.mtu`, so a response larger than it leaves as IPv4 fragments
  rather than as one oversized raw packet the packet topology could not carry. Fake-DNS replies go out through that
  same netif rather than straight at the neighbour: a maximum multi-question answer is around 776 bytes, past common
  small IPv4 MTUs. PTC accepts the core's legal minimum MTU of 68 bytes. The reply is submitted as a UDP datagram
  through `ip4_output_if()`, so lwIP constructs
  the IPv4 header, allocates the shared identification value, and applies fragmentation with stack-owned offsets, MF
  flags, per-fragment lengths, and checksums. That publication happens while `LOCK_TCPIP_CORE()` is held, which is legal
  because the netif output callback only queues a packet message - it never calls the neighbour inline
- packet emission is protected by an admission gate held through the previous-neighbour callback, and normal-line
  `Init`/`Payload`/`Resume`/`Finish` work uses a second gate held through the next-neighbour callback. Global shutdown
  closes both gates in `onQuiesceRequest()` and waits for admitted callbacks in `onQuiesceWait()` before any component
  stops, so an already-admitted callback finishes before its neighbour can stop and queued work that runs later is cancelled. A
  refused next-side ordinary work recycles anything it owns and leaves teardown to the owner path; an initialized line
  still receives its one explicit teardown `Finish` during the owner-worker drain
- netif output is always queued, even to the same worker, so no neighbouring callback runs while lwIP's non-recursive
  core lock is held. Under lifecycle-v2, all pending worker messages settle before component stop and destruction;
  quiesce closes the output admission gate so queued work running during quiescence cancels cleanly without calling into
  a stopped neighbour. Fake-DNS lookup, response construction, and submission to lwIP remain under the core lock; only
  delivery of the queued output messages to the previous neighbour happens after the outer packet handler unlocks
- top-level packet parsing reads only the version byte before normalizing cursor alignment. Shifted packet buffers are
  copied to aligned sbuf storage before any typed IPv4/UDP access; fake-DNS additionally validates the IPv4 header and
  any nonzero UDP checksum before it can answer or mutate its mapping cache
- a device-originated fragment carries a ref-counted settlement claim with its packet buffer through alignment copies,
  duplication, delay, worker handoff, and cleanup. Immediately after lwIP input, PTC queries the exact reassembly key
  (netif, source, destination, protocol, and identification); `ERR_OK` alone is not treated as acceptance. Explicit
  refusals purge that exact key. An identity is released promptly only when the stack proves that no residue remains;
  a retained or unknown outcome keeps it reserved so a delayed same-ID packet cannot form a hybrid datagram. Its
  release barrier requires both the full elapsed reassembly interval and `IP_REASS_MAXAGE + 1` actual synchronized
  lwIP reassembly-timer passes; a suspended or starved timer cannot be mistaken for stack retirement
- every generated TCP/UDP line is registered in a per-worker owner list until its one close path unlinks it. Stop first
  detaches PCB, route-map, callback, and UDP-idle producers under the core lock, then drains each owner-worker list,
  preserves whether next-side `Init` completed, destroys PTC line state, sends exactly one next-side teardown `Finish`
  when required, and calls `lineDestroy()`. Configuration Stop waits for all worker drains; terminal worker
  shutdown performs the same drain locally without relying on new message admission
- Stop explicitly detaches every owned per-flow UDP PCB, wildcard UDP PCB, and TCP listener before removing its netif.
  WaterWall's lwIP patch treats that as a raw-owner precondition and rejects `netif_remove()` if either raw owner is
  still present; it never silently frees a pointer the tunnel could still retain. A failed conversion from a full TCP
  PCB to a listener also closes or aborts that full PCB before the route is retried

This keeps line destruction and tunnel state teardown on the normal Waterwall line side instead of relying on ad-hoc cross-worker message ownership.

The internally created TCP/UDP lines are normal connection lines. They are separate from the persistent worker packet line and may be closed and destroyed during normal runtime.

## Finish / Close Behavior

When the network side closes a flow:

- a connected TCP PCB moves to an instance-owned closer, even when the application queue is empty
- the closer copies only the suffix `tcp_write()` has not accepted; bytes already copied into lwIP are never duplicated
- receive credit is returned, peer data is consumed, and a TX-only `tcp_shutdown()` sends FIN after every accepted byte
- this tunnel destroys its own line state
- if upstream `Init` was already sent, upstream `Finish` is propagated
- the internally created line is then destroyed by `PacketsToConnection`

When the next tunnel sends downstream `Finish`:

- `PacketsToConnection` transfers a connected TCP PCB to the same graceful closer
- destroys its own line state
- destroys the internally created line

It does not reflect that downstream `Finish` back toward upstream.

The closer has monotonic delivering, FIN-pending, and closing phases. Delivery and peer-close deadlines are bounded at
30 and 60 seconds, and one instance may retain at most 4096 closers and 16 MiB of copied suffixes. Allocation, capacity,
terminal write, or deadline failure resets that flow; Stop aborts all active closers before route/netif removal.

That matches Waterwall's direction rules for internally created lines.

The shared packet line is not destroyed by these flow closes. It remains alive until the tunnel chain is destroyed.

## Pause / Resume

### TCP

TCP backpressure is integrated with Waterwall:

- if lwIP cannot accept all downstream bytes, remaining data is queued
- upstream is paused with `tunnelNextUpStreamPause()`
- lwIP sent callbacks flush the queue, and `tcp_poll` supplies bounded progress when the first write accepted nothing
- upstream is resumed with `tunnelNextUpStreamResume()` when writable again
- acknowledgement records keep their totals and remaining-byte arithmetic at 32 bits, so one stream buffer may exceed
  65535 bytes even though each individual lwIP sent callback reports a 16-bit count. Empty TCP buffers are consumed
  without entering the write or acknowledgement queues

For receive-side backpressure:

- downstream `Pause` stops immediate `tcp_recved()`
- downstream `Resume` releases the deferred receive credit

### UDP

UDP has no true stream backpressure model.

Current behavior:

- downstream `Pause` marks the flow paused
- inbound UDP datagrams received while paused are dropped
- downstream `Resume` clears the paused state
- downstream application payloads are limited to the IPv4 UDP maximum of `65507` bytes; larger buffers are dropped
  without narrowing through lwIP's 16-bit APIs, while an empty UDP payload remains a valid header-only datagram

This is intentional and should be treated as a current limitation of the UDP path.

## JSON Settings

`PacketsToConnection` currently supports:

- `udp-idle-timeout-ms` `(int, default: 300000)`
  Controls how long an idle UDP flow line is kept alive before the tunnel closes it.
- `max-pending-bytes` `(int, default: 262144)`
  Upper bound on the TCP payload one flow may retain while lwIP has not yet taken or acknowledged it. Valid range
  `1024` .. `67108864`. Passing it sheds that one flow.
- `fake-dns` `(bool or object, default: false)`
  Enables an in-tunnel fake DNS responder for IPv4 A queries. Mapped fake-IP destinations are converted back into domain destinations on generated TCP/UDP Waterwall lines.

The minimum allowed `udp-idle-timeout-ms` value is `1`.

`Pause` is advisory between tunnels, so it cannot be the only bound on retained memory: the next tunnel may already
have a payload callback queued, may race the pause, or may simply ignore it. `max-pending-bytes` is therefore an
admission limit, checked before the payload is queued and counted exactly - both the bytes waiting for lwIP's send
window and the bytes already written but not yet acknowledged. A payload that would pass the limit is dropped, the
flow's TCP connection is reset rather than drained, and the line is closed toward the next tunnel. UDP retains
nothing downstream, so the limit does not apply to it.

One TCP flow may also retain at most 1,024 ACK/pause records, independently of the byte limit. This is an internal
allocation-safety cap, not a JSON setting: it bounds record overhead for streams split into tiny callbacks. Reaching
the next entry resets and closes only that TCP flow. It does not affect UDP flows.

`fake-dns` object fields:

- `enabled` `(bool, default: true)`
- `address` `(IPv4 string, default: "198.18.0.2")`
- `port` `(int, default: 53)`
- `network` `(IPv4 string, default: "100.64.0.0")`
- `netmask` `(contiguous IPv4 /1 through /31 prefix mask, default: "255.192.0.0")`
- `cache-size` `(int, default: 10000, maximum: 262144)`
- `ttl` `(int seconds, default: 1)`

The legacy key `mapdns` is accepted as an alias for `fake-dns`. The key `fake_dns` is also accepted. Exactly one of
these spellings may be present; duplicate aliases are rejected even when their values are equal. A disabled object is
still validated field by field but does not allocate fake-DNS tables.

`address` must be a concrete, non-loopback IPv4 unicast source. Wildcard, loopback, multicast, and limited-broadcast
addresses are rejected so lwIP never rewrites or emits an unusable reply identity. The listener may share the fake
network prefix only when its host index is outside `[0, cache-size)`; it cannot overlap an address allocated to a fake
record. The first index immediately after that interval remains valid.

Every setting above is validated rather than defaulted on error. Only an omitted key selects its default; a value of
the wrong JSON type, a fractional integer, or one outside the accepted range fails node creation and names the exact
JSON path. A rejected DNS query also leaves the cache alone: the whole question section is parsed and validated before
the first mapping is created. All unique A/IN names in one query are committed as one cache transaction; if they cannot
coexist, or any allocation/insertion fails, the response contains no fake answers and the old forward map, reverse
records, and LRU order remain unchanged. Duplicate questions reuse one mapping. The mask must be contiguous and leave
at least one host bit: `/32` is rejected because it provides no indexed address space, while `/0` necessarily
normalizes to the zero range and is rejected by the rule below. A cache may contain at most `2^(32 - prefix)` records,
including both endpoint addresses of the prefix (`/31` therefore supports exactly two). The configured network is
masked to its prefix, record index zero maps to that masked address, and indexes carry across IPv4 octets normally. Any
range whose first record would be the reserved `0.0.0.0` failure sentinel is rejected.
The product limit of 262144 records bounds the eagerly allocated record index and reserved name-map storage to roughly
16 MiB on a 64-bit build. Allocation multiplication, signed map capacity, load-factor growth, and the map's next
power-of-two bucket count are all validated before either allocation is attempted.

### Example

```json
{
  "name": "ptc",
  "type": "PacketsToConnection",
  "settings": {
    "udp-idle-timeout-ms": 120000,
    "max-pending-bytes": 262144,
    "fake-dns": {
      "address": "198.18.0.2",
      "network": "100.64.0.0",
      "netmask": "255.192.0.0",
      "cache-size": 10000
    }
  },
  "next": "service-chain-entry"
}
```

## Typical Placement

Example packet-to-service chain:

```text
TunDevice <--> PacketsToConnection <--> TcpConnector
```

or:

```text
WireGuardDevice <--> PacketsToConnection <--> HttpClient
```

The key idea is that the previous side is packet-oriented, while the next side is normal Waterwall connection-oriented chaining.

## Limitations

- IPv6 is not implemented
- fake DNS answers from a single packet, so fragmented **UDP** addressed to its endpoint is dropped with a
  rate-limited warning rather than parsed; a fragment used to be consumed silently, which stopped reassembly
  from ever completing. The destination port cannot be checked, because only fragment zero carries a UDP
  header and reading one out of a later fragment's payload bytes would be guessing - so the whole address is
  reserved for fragmented UDP, not only for fragmented DNS. Fragmented TCP to that address is unaffected and
  is routed normally
- the zero-copy receive path wraps each incoming packet in a pooled descriptor whose size is derived in
  `ww/lwip/lwipopts.h` from the shared reassembly budget *and* the TCP flow target. Both matter: one fragment
  held for reassembly pins one descriptor, and so does one TCP segment held out of order - the larger consumer
  of the two, and unlike `PBUF_POOL` exhaustion it does not trigger lwIP's out-of-order reclamation. The
  resulting figure is headroom rather than a hard bound - one wrapper per advertised flow, plus the reassembly
  budget and a fixed reserve. One incomplete IPv4 datagram may retain at most 16 pbufs (counting chained pbufs);
  exceeding that cap purges only the offending datagram, so unusually extreme fragmentation is refused without
  evicting unrelated reassemblies. What makes the TCP part a bound is the per-PCB
  `TCP_OOSEQ_MAX_PBUFS`/`TCP_OOSEQ_MAX_BYTES`
  ceiling beside it. The 32-pbuf ceiling is the effective bound; the byte ceiling is an intentionally unreachable
  future-defense guard at the current receive window. Exhaustion past the active bound drops
  one packet with a rate-limited warning. This wrapper pool is process-global and initialized exactly once even when
  multiple `PacketsToConnection` instances are created; Stop, Destroy, and hot replacement never reset live wrappers
- packet transforms may leave the buffer cursor at any byte alignment, and lwIP reads typed IP/TCP headers
  straight out of it, so that exceptional case is copied into an aligned buffer and travels through the same
  custom-pbuf wrapper as everything else. It is deliberately *not* copied into an lwIP `PBUF_RAM`: with pooled
  heap allocation the largest class is 16 KiB including overhead, which silently dropped every valid misaligned
  IPv4 packet above roughly that size while the aligned path beside it had no such ceiling
- ICMP is not implemented
- UDP pause is lossy, not queued
- IPv4 route/netif contexts are created on demand per packet worker, not per destination IP, and are not currently exposed as a tuning surface
- lwIP has 255 process-wide netif indices. Loopback and every lwIP-using node share them; a paired
  `ConnectionToPackets`/`PacketsToConnection` topology can consume roughly `1 + 2 * workers` netifs. Capacity
  exhaustion fails creation promptly rather than hanging
- TCP and UDP listeners are pretend wildcard PCBs on the worker-local netif, not one listener per destination port
- fake-DNS configuration validates its contiguous prefix, usable address range, 262144-record product cap, reserved
  name-map geometry, and record-array byte count before allocating or enabling the cache. Every multi-question response
  pins existing answers, stages all new mappings and victims, and commits them together; allocation, insertion, or
  coexistence failure returns no fake answer and leaves existing usage, LRU order, forward map, and reverse records
  unchanged
- this node assumes packet payload really is IP traffic and does not validate every malformed edge case beyond conservative basic checks
- this node is not a packet-framing tunnel and does not add per-payload headers; its node declares no extra left-padding requirement

## Difference From PacketsToStream

Use `PacketsToStream` when you only need to preserve packet boundaries over a stream transport.

Use `PacketsToConnection` when you need lwIP to reconstruct transport flows and expose them as normal Waterwall lines.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` &#124; `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer3` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `0` bytes |
