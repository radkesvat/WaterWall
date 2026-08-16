<!--
Documentation version: 150
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/ConnectionToPackets.mdx, and both files must keep the same documentation version.
-->

# ConnectionToPackets Node

`ConnectionToPackets` is the active-open inverse of `PacketsToConnection`. It takes an ordinary WaterWall connection
line, opens the matching TCP or UDP flow inside an in-process lwIP stack, and emits the resulting raw IPv4 packets on
the chain's packet side. Return packets arriving on the packet side are injected back into that flow, and the data
comes out as normal downstream payload on the original connection.

```text
ordinary WaterWall connection line
        -> ConnectionToPackets
        -> raw IPv4 TCP/UDP packets on the worker packet line

return IPv4 packets
        -> ConnectionToPackets
        -> downstream data/events on the original connection line
```

## What It Is

This is a userspace transport bridge, not a transparent replacement for an OS TUN interface. It needs no kernel TUN
device, no raw socket, and no root privileges.

Local applications must enter WaterWall through a connection adapter such as `TcpListener`, `UdpListener`,
`TcpUdpListener`, or `Socks5Server`. Capturing arbitrary traffic from unrelated kernel sockets is outside this node's
scope and still requires an OS routing or VPN mechanism.

## Topologies

The smallest rootless end-to-end topology is a direct composition with `PacketsToConnection`:

```text
TcpListener -> Socks5Server -> ConnectionToPackets
            -> PacketsToConnection -> TcpUdpConnector -> destination
```

A practical encrypted topology sends the packets through WireGuard:

```text
local application
  -> listener or SOCKS node
  -> ConnectionToPackets
  -> WireGuardDevice
  -> UdpStatelessSocket

remote UdpStatelessSocket
  -> WireGuardDevice
  -> PacketsToConnection
  -> TcpUdpConnector
  -> destination
```

The configured virtual source address must be routable back through the packet topology. For WireGuard, the local side
normally selects the peer with a destination route such as `0.0.0.0/0`, and the remote peer must allow the configured
virtual source address, usually as a `/32`.

## Scope

Supported:

- IPv4 TCP
- IPv4 UDP, including datagrams larger than one MTU
- IP destinations, and domain destinations through the internal `DomainResolver`
- multiple WaterWall event workers

Rejected or dropped:

- IPv6, permanently: see below
- ICMP and every other non-TCP/UDP protocol
- UDP payloads above `65507` bytes, which have no valid IPv4 encoding
- return packets that match no registered flow

ICMP error delivery and preserving the application's original source port are follow-up work.

### IPv4 Only, By Design

This node emits IPv4 and nothing else. That is a product decision rather than a missing feature: it exists to bridge a
connection into a packet topology whose far side is an IPv4 stack, and an IPv6 packet on that side would have nowhere
to go.

The contract is enforced at both ends:

- `domain-strategy` accepts only `only-ipv4`, so an AAAA-only domain fails DNS with a name in the message instead of
  resolving to an address this node then has to reject
- a destination that is nonetheless IPv6 closes that one line with an explicit error

Global lwIP IPv6 support is untouched: the stack is shared with every other lwIP-using node in the process.

## Checksum Finalization Boundary

On return-side packet ingress, `ConnectionToPackets` is the final consumer of the packet line's one-packet checksum
recalculation request. It takes and clears that request before any validation or drop path, normalizes the packet into
mutable aligned storage, and then repairs the supported checksums before handing bytes to lwIP. A malformed, IPv6,
stopping, or refused packet therefore cannot leak its request into the next unrelated packet on the worker line.

For an unfragmented IPv4 TCP or UDP packet, finalization repairs the IPv4 header and transport checksum. For an IPv4
fragment, only the IPv4 header checksum can be repaired from that fragment; the node never invents a whole-datagram
TCP or UDP checksum from incomplete transport bytes.

## Fragmentation

A UDP datagram larger than the configured MTU is emitted as IPv4 fragments rather than dropped. The whole datagram is
handed to lwIP, which splits it in `ip4_frag()`, so the identification, offsets and `MF` flag are the stack's rather
than this node's.

Return fragments are routed back through an association table. Only fragment offset zero carries the transport ports
the flow registry is keyed on, so that fragment resolves the datagram's owning flow and every other fragment of the
same datagram follows it to the same worker - which matters because lwIP reassembles into whichever netif completed the
datagram, and the per-worker netifs are not interchangeable. Fragments that arrive before fragment zero are held,
bounded by count and by total bytes, and released if the rest of the datagram never arrives.

An association exists only while its datagram is in flight or its queued worker work is being settled. Received byte
ranges identify completion, but the entry is not retired merely because the last fragment was classified: a final FIFO
barrier runs on the owner worker after every earlier injection task, purges the exact lwIP reassembly key, and only then
makes the IPv4 identification reusable.

Coverage is tracked the way lwIP tracks it rather than as a set union. lwIP is built with overlap checking and discards
a duplicate or overlapping fragment, so this table rejects them too: absorbing an overlap would make a datagram look
complete - and hand its identification back - while the real reassembler still had a hole in it. Only adjacency is
merged. A fragment that contradicts what its datagram is already known to be is refused on the same grounds: data past a
known final end, a second last fragment claiming a different total, or a last fragment that would truncate ranges
already recorded.

lwIP's reassembly list is keyed on ingress netif, source, destination, protocol and identification. The netif part keeps
same-ID traffic routed to different workers independent; the remaining identity still must not be reused on one worker
while older queued work can leave a partial datagram behind. Two states prevent that:

- while fragments are publishing, or after any injection enqueue/revalidation failure, the identification stays
  reserved and matching traffic is dropped until its owner-worker purge barrier completes
- a second fragment zero is ambiguous even when it names the same flow: without a content fingerprint it may be a
  duplicate or a newer datagram reusing the ID, so it poisons and purges the old association instead of mixing either
  interpretation

The deadline cannot expire while an admitted owner-worker injection is still queued. After a fragment is actually
accepted by the exact lwIP netif, a healthy incomplete association is kept for at least another full timeout from that
delivery (without shortening a later deadline). Queue admission or classification alone does not refresh it. A refused
or cleaned injection instead poisons the identification and orders the exact FIFO purge barrier, so delayed worker
delivery cannot either lose a valid datagram early or leave a hybrid reassembly behind.

The bounds are deliberate and shed rather than grow, each with a rate-limited diagnostic:

- at most `128` datagrams may be associating at once
- at most `16` fragments, and `1 MiB` across the whole node, may wait for a fragment zero
- at most `16` disjoint byte ranges per datagram, which is what bounds pathological reordering
- an incomplete association expires after `15` seconds; unresolved staged data is released directly, while an
  association that may have reached lwIP remains poisoned until its worker purge barrier completes

Structurally impossible fragments are refused before any of that: a reserved flag, `DF` combined with fragmentation, an
empty fragment, a non-final fragment whose payload is not a multiple of eight, a fragment carrying IP options, a bad
IPv4 header checksum, and anything reaching past the largest payload lwIP will reassemble (`65535 - 20` bytes). Each of
these is something lwIP itself drops, so accepting one here would occupy an association and record coverage for a
datagram the stack is never going to assemble.

Every packet of one flow, fragmented or not, is sent to the same packet worker. A next node that keeps per-flow state -
`PacketsToConnection` does - pins that state to the worker that first saw the flow, and the shared packet-worker hash
falls back to the IPv4 identification when a fragment has no ports, which would otherwise scatter one flow's datagrams
across workers.

The node's own outbound TCP does not fragment: its send MSS is derived from the same MTU. Return-side IPv4 TCP
fragments from the packet neighbour are nevertheless valid input. Fragment zero need carry only the source and
destination ports; the fragments stay on the resolved owner worker and lwIP validates the complete TCP header after
reassembly. If that completed chain still splits the TCP header, lwIP first validates the declared 20-through-60-byte
TCP header length, then copies exactly the required 40-through-80-byte IPv4-plus-TCP prefix into a small contiguous
head and leaves the rest of the pbuf chain in place. Acceptance therefore does not depend on whether either the TCP
options or the complete datagram fit in one original pbuf or one heap class.

A device-originated fragment settlement claim follows the packet across the aligned copy, fragment staging, owner
worker handoff, and lwIP input. Every refusal, expiry, or Stop path resolves the claim exactly once. When the exact
live netif is still available, ConnectionToPackets purges or queries the precise IPv4 reassembly key before reporting
`NoResidue` or `ResiduePresent`; an immediately refused owner-worker publication retains its claim until that exact
purge has completed. If absence cannot be proved, it conservatively reports `Unknown`.

## Settings

| Setting | Required | Default | Meaning |
| --- | --- | --- | --- |
| `source-ipv4` | yes | none | Virtual IPv4 source assigned to the per-worker lwIP netifs and to every actively opened PCB. There is deliberately no default, because a silently chosen address would eventually collide with a real one. Must not be `0.0.0.0`, a loopback, multicast, or broadcast address. |
| `mtu` | no | core `misc.mtu` | Raw IP MTU of the virtual netifs. Valid range `576` .. `9000`. TCP derives its send MSS from it; UDP fragments above it. An inherited core value outside the range is a configuration error, not something to round into range. Core `misc.mtu` is itself validated as a whole number in `68` .. `65535` before it is stored, so it can no longer wrap into a different MTU or into zero. |
| `domain-strategy` | no | `only-ipv4` | `only-ipv4` is the only accepted value. Every other strategy can hand this node an address it cannot use: the two IPv6 ones directly, `prefer-ipv4` through its AAAA-only fallback, and `accept-dns-returned-order` by preferring neither family. |
| `tcp-connect-timeout-ms` | no | `30000` | Deadline for the active TCP open. On expiry the line is closed toward the previous node. |
| `max-pending-bytes` | no | `262144` | Upper bound on application data retained before the connection is established or while lwIP's send window is full. Valid range `1024` .. `67108864`. Passing it sheds that one flow. |

Every optional number is validated rather than defaulted on error. A wrong type, a fractional value, and an
out-of-range value all fail configuration with the field named; only an *absent* field takes the default.

Example:

```json
{
  "name": "connection-to-packets",
  "type": "ConnectionToPackets",
  "settings": {
    "source-ipv4": "10.90.0.1",
    "mtu": 1420,
    "domain-strategy": "only-ipv4",
    "tcp-connect-timeout-ms": 30000,
    "max-pending-bytes": 262144
  },
  "next": "wireguard-device"
}
```

## Destination And Protocol Selection

Protocol selection is deliberately identical to `TcpUdpConnector`, so both nodes accept exactly the same lines:

- an exact destination-context protocol wins
- otherwise an exact source-context protocol is used
- a missing or ambiguous protocol rejects that one line

The destination address and port come from the line's destination context. A domain is resolved by an internal
`DomainResolver` inserted directly in front of this node during chaining, so the emitted packet already carries the
resolved IP.

There is no fake DNS here. Preserving the original domain for policy decisions on the remote `PacketsToConnection` side
would need a separate metadata protocol and is not part of this node.

## Flow Control

TCP applies real backpressure in both directions:

- application data that lwIP cannot accept yet is queued, bounded by `max-pending-bytes`, and a `Pause` is sent toward
  the previous node until the send window drains
- received data is delivered downstream first; if the previous node pauses re-entrantly, the receive credit is withheld
  instead of being returned to lwIP, which closes the TCP window until it resumes

In addition to the byte limit, one TCP flow may retain at most 1,024 queued payload entries. This internal
allocation-safety limit is not JSON-configurable: it bounds per-buffer/deque overhead even when callbacks contain only
one byte. Crossing it resets and closes only the offending TCP flow. UDP has no stream pending queue and is unaffected
by either retained-entry accounting or queue allocation pressure.

UDP backpressure is intentionally lossy: while the previous node is paused, received datagrams are dropped rather than
queued without bound.

## Lifecycle Notes

- The connection line is **borrowed**. This node initializes and destroys only its own line state and never calls
  `lineDestroy()`; the listener or adapter that created the line destroys it.
- The per-worker packet lines belong to the chain. They are never initialized as flows and never destroyed at runtime.
  A `Finish` on a packet line is a contract violation and aborts the process.
- Construction is staged: the netif pointer array, the flow registry, and the async session are each committed before
  the next is attempted, and every failure unwinds through the one `onDestroy()` path. That path decides what to
  release from the state each stage published rather than from how far construction got, so a flow-registry sweep is a
  no-op until the registry exists - the registry owns `flows_lock`, and locking one that was never created, or one its
  own rollback already destroyed, is undefined behavior rather than a recoverable error.
- Because the chain may start with a layer-4 adapter, the packet side is initialized from `onStart()` with one queued
  task per worker rather than by the node manager's layer-3 head initialization.
- A gracefully closed TCP flow leaves a tombstone in the flow registry so late FIN/ACK traffic still reaches the right
  worker and netif. It is a routing grace period of `2 * TCP_MSL`, not a model of the PCB's lifetime. The node-owned
  closer uses TX-only `tcp_shutdown(pcb, 0, 1)` and tracks the PCB through `FIN_WAIT_1`, `FIN_WAIT_2`, `CLOSING`, or
  `LAST_ACK`; it does not use `tcp_close()` for a connected flow. When lwIP moves the PCB to `TIME_WAIT`, the closer
  detaches its application callbacks and retires its live registry entry immediately, leaving only lwIP to own the
  `TIME_WAIT` PCB. The separate tombstone may therefore outlive that PCB or expire before it; neither loses a live flow.
- Tombstones are held in a fixed `4096`-entry retirement ring rather than each holding its own worker timer - a timer
  per close made both the timer queue and shutdown cost grow with connection churn. The ring is what makes the bound
  hard: more flows can close inside one grace period than an age-based sweep would be allowed to remove, so past the cap
  the oldest tombstone gives up its place. Expiry is also honoured at lookup, so a node that has gone quiet - and
  therefore never registers or retires anything - cannot keep answering for a tuple whose grace period has passed.
- A registration that lands on a tombstone replaces it. lwIP has already chosen that exact local port, so refusing would
  trade an accepted late-packet ambiguity for a visible connection failure.
- A local `Finish` or clean remote half-close first flushes accepted TCP bytes. The PCB then moves to a node-owned
  closer, which a *connected* flow takes even with nothing left queued: bytes already inside lwIP may still be
  unacknowledged, the peer may still be sending with nobody left to credit it, and its acknowledgements have to keep
  routing to this worker. During that handoff, every byte already copied out of lwIP but not yet passed to
  `tcp_recved()` is returned before the line's PCB pointer is cleared. This includes still-queued owner tasks and the
  paused subset, so the closer inherits a fully reopened receive window and each accepted byte is credited once.
- The closer writes until the peer has every accepted byte and then requests a TX-only shutdown. Its tuple stays
  registered as *draining* - neither active nor a tombstone - so it cannot be evicted while this node still owns the
  PCB. A `30` second deadline covers both queued-byte delivery and a FIN that lwIP has accepted but cannot yet allocate.
  In that latter state `tcp_shutdown()` returns success with `TF_CLOSEPEND`; the closer keeps its callbacks, registry
  ownership, and deadline, and records peer EOF without retiring. An actual transition to `FIN_WAIT_1`, `FIN_WAIT_2`,
  `CLOSING`, or `LAST_ACK` with `TF_CLOSEPEND` clear means the FIN was queued; this real state is reconciled before the
  pending-FIN deadline, so a transition made by the same timer tick wins at deadline equality. `TIME_WAIT` is graceful
  terminal reconciliation and retires the closer without aborting the PCB. A separate `60` second peer-close deadline
  covers active closing states. Closers are also bounded by a shared `16 MiB` byte budget and a `4096` object count;
  past any bound, the PCB is aborted exactly once rather than reporting a clean but truncated EOF or leaving an
  untracked PCB.
- The FIN is sent with a TX-only shutdown, never `tcp_close()`. lwIP resets and frees a PCB whenever `tcp_close()` runs
  in `ESTABLISHED` or `CLOSE_WAIT` with receive credit outstanding - and this node returns credit from an owner-worker
  task, and withholds it entirely while the previous tunnel is paused, so that is the ordinary state rather than an
  exceptional one. The reset would have taken every unacknowledged outbound byte with it, which is precisely what the
  closer exists to prevent. Only a flow that never reached a connected state still closes, where the rule cannot apply.
- A write lwIP refuses with `ERR_MEM` is retried from a `tcp_poll` callback installed for exactly as long as the write
  stays blocked. `tcp_sent` alone was not enough: a first write that fails on an otherwise idle PCB leaves nothing
  unacknowledged, so no acknowledgement was ever coming and the line stayed paused after the pressure cleared. Any other
  write error is terminal and closes the flow once instead of being retried forever.
- The active-open deadline is a cancellable per-line timer owned by that line's event worker, holding exactly one line
  reference. A successful connection cancels it immediately: a fire-and-forget delayed task would have kept its message
  and the line allocation behind it alive for the whole configured timeout, up to the ~49.7 days a `uint32_t`
  millisecond count can express.
- A generation counter stops a *queued* packet of an old flow from being injected into a new flow that reused its tuple
  between lookup and delivery, and it is revalidated under the lwIP core lock immediately before injection. It cannot
  identify a packet that arrives from the network after a tuple was retired and reused, because an IP packet carries no
  generation. Tombstones reduce that late-network-packet window but cannot eliminate it.
- `onQuiesceRequest()` publishes stopping, closes new admission through the previous-side, next-side,
  packet-classification/publication, and asynchronous-session gates, and requests callback detachment without waiting.
  `onQuiesceWait()` then proves already-admitted callbacks have returned. Emit, inject, fragment-purge, and startup
  packet-`Init` messages retain a small async session rather than the tunnel pointer, so a canceled queued message can
  release its own resources. After worker-owned lines drain, `onStop()` detaches every PCB, flow, netif, and staged
  fragment under the lwIP core
  lock. TCP PCBs are **aborted** there rather than closed: Stop is terminal, the gate already refuses this node's netif
  output, and a successful close would have left an established PCB sitting in `FIN_WAIT` on lwIP's process-global
  active list - outliving the netif removed moments later, and able to observe whichever future interface inherits that
  one-byte netif index. It also clears each live line's copy of its PCB pointer so a worker that has not drained yet
  cannot dereference a released PCB. Publishing `stopping` is not treated as proof that this sweep already happened:
  a close that acquired the core lock during the quiesce-request window performs the real idempotent
  PCB/callback/registry detach.
  Every queued task enters the relevant gate, so a rejected task suppresses its data and lifecycle events
  toward either neighbour, while close paths stay live so borrowed lines can still be released by their owners.
- Creation publishes no partially usable bridge: the per-worker netif array, initial flow and fragment map capacities,
  fixed tombstone ring, and asynchronous session are mandatory. If any allocation is unavailable, initialized pieces
  are unwound and node creation returns failure before a flow callback can run.
- If lwIP replays refused receive data from its real timer thread, the callback leaves the original pbuf retained,
  latches one retry, and queues `tcp_process_refused_data()` to the flow's owner worker. Owner-pool access and delivery
  therefore remain worker-correct, including a data-plus-FIN replay. A required control enqueue refusal first detaches
  the exact PCB callbacks and route under the lwIP core lock and publishes the borrowed line in the preallocated
  owner-worker terminal registry. Orderly process shutdown is escalation after that terminal handoff; cleanup does not
  depend on the refused queue or on Stop rediscovering the flow.
- Borrowed lines are finished and destroyed later by their real owners.

## Capacity

All lwIP-using nodes share one global set of statically sized pools, configured in `ww/lwip/lwipopts.h` and
`ww/lwip/lwippools.h`. Four CMake cache variables size them, each validated as a positive integer and forwarded to
every target that includes `lwipopts.h` - the pools are static arrays whose sizes are baked into both `ww_lwip` and the
tunnels, so they must be one value for the whole build:

| Variable | Default | What it sizes |
| --- | --- | --- |
| `WW_LWIP_MAX_TCP_FLOWS` | `2048` | TCP PCBs and the TCP segment pool |
| `WW_LWIP_MAX_UDP_FLOWS` | `2048` | UDP PCBs |
| `WW_LWIP_MAX_REASS_DATAGRAMS` | `32` | simultaneously reassembling fragmented datagrams |
| `WW_LWIP_MAX_TCP_LISTENERS` | `320` | listener PCBs; `PacketsToConnection` needs one per packet worker that sees TCP, and up to 254 workers are supported |

Every derived pool is checked at configure time as well as by preprocessor guards, so an override that would overflow
lwIP's `u16_t` counters fails before the build starts.

The `mem_malloc` heap classes in `lwippools.h` are derived from **both** flow targets, because a UDP flow allocates
`PBUF_RAM` from that same heap for every datagram it sends. Division is rounded up and floored at one entry, so a small
override shrinks a size class rather than deleting it. The hot class holds a full-MSS segment copy; its size is computed
from the transport headroom, `TCP_MSS`, and the allocator's own overhead, and a static assertion fails the build if a
future change to headroom or alignment pushes a normal write past it. It was previously 1536 bytes, which no normal
full-MSS write could fit, so every one of them skipped the class entirely.

The reassembly budget is deliberately independent of the flow targets: reassembly capacity is a function of how many
*fragmented* datagrams are in flight, not of how many flows exist. Each incomplete datagram may retain at most 16 pbufs
(including every element of an incoming pbuf chain), which covers an 8 KiB datagram at the smallest supported MTU
(576). A seventeenth pbuf purges only that offending datagram instead of evicting unrelated reassemblies. More
extremely fragmented return datagrams are therefore refused. The global budget remains 32 datagrams times 16 pbufs,
and `PBUF_POOL_SIZE` is held at three times that budget so a full reassembly backlog cannot starve the receive path.
Return packets are injected as reference pbufs rather than copied into pool buffers, so one wire packet normally costs
exactly one unit of that budget - which is the unit lwIP charges.

`PacketsToConnection`'s zero-copy receive path derives its wrapper-pool size from that budget plus the advertised TCP
flow count plus a fixed reserve. Reassembly is not its only consumer: every segment TCP retains out of order also pins a
wrapper, and unlike `PBUF_POOL` exhaustion, wrapper exhaustion does not trigger lwIP's out-of-order reclamation - so a
pool sized for reassembly alone could be emptied by ordinary reordering across the flow target and then drop the very
retransmissions that would have freed it. A per-PCB `TCP_OOSEQ_MAX_PBUFS` ceiling keeps one peer from spending the
shared reserve.

The previous development-sized values let five concurrent TCP flows exhaust the whole process, and could not reassemble
a single fragmented 8 KiB datagram.

These pools are static. With the documented defaults a Linux release build has roughly **9.6 MB total BSS**, about an
**8.6 MB increase** over the earlier development-sized pools' roughly 1.0 MB. Lower the cache variables to trade
concurrency back for memory on a constrained target; a value large enough to overflow lwIP's `u16_t` pool counters
fails the build instead of silently truncating.

lwIP also has a process-wide namespace of 255 simultaneous netif indices. The loopback interface and every other
lwIP-using node count against it. A paired `ConnectionToPackets`/`PacketsToConnection` topology can consume roughly
`1 + 2 * workers` netifs, so other lwIP nodes may make the practical worker limit lower. Exhaustion now fails netif
creation promptly and sheds the affected flow instead of hanging in `netif_add()`.

Pool exhaustion always closes or sheds the affected flow, with a rate-limited diagnostic; it never aborts the process.

## Composition Notes

- The previous node must be layer 4 and the next node must be layer 3.
- A `next` node is required: it is where the packets go.
- Placing this node in a chain makes that chain a packet chain, so per-worker packet lines are allocated for it.
