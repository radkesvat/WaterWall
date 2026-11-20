<!--
Documentation version: 164
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/RawSocket.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/RawSocket.mdx, and all files must keep the same documentation version.
-->

# RawSocket Node

## Overview

`RawSocket` connects WaterWall to raw IPv4 packet capture and raw packet injection. When capture ranges are configured, it captures matching IP packets from the host networking stack and forwards them into the chain. Independently, it can inject raw IP packets coming from the chain back into the system.

This node is a layer-3 adapter rather than a connection-oriented tunnel.

For Ping/Ping6 paths that rewrite addresses, place IpOverrider between RawSocket
and the decoder and select `"opaque-flow-mode": "peer"` explicitly; `auto`
recognizes only direct decoder neighbours. All Ping modes reuse the IPv4 header.
Ordinary Ping and direct Ping6 add nine bytes and accept at most 1491 complete
native bytes; `ipv6-in-ipv4` Ping6 adds 49 and accepts at most 1451. Both entry
points reject fragments. Configure `"fragment-policy": "reassemble"` on adapters
and budget device/bridge MTUs for the actual path. Capture the peer's network
address with protocol 1 for Ping, 58 for direct Ping6 or 41 for IPv6-in-IPv4 Ping6. Ordinary Echo traffic may
satisfy the layout; dedicated capture selection supplies no authentication.

### What It Does

- Optionally creates a capture device for matching IPv4 packets.
- Creates a raw output device for sending raw IPv4 packets.
- When capture is enabled, captures packets that match the configured IP and protocol filters and drops them from the host kernel network stack so only WaterWall receives and accesses them.
- Forwards captured packets to the adjacent chain side.
- Writes raw IP packets from the chain out through the raw device.
- Applies checksum recalculation before writing when the packet buffer requests it.
- Bypasses Linux conntrack for active captured input and raw output; output uses a dedicated explicit or automatic socket mark.

## Typical placement

`RawSocket` can be placed at either edge of a chain:

- if it is last in the chain, captured packets are forwarded to the previous node
- otherwise, captured packets are forwarded to the next node

Payload reaching `RawSocket` from upstream or downstream is treated as an IP packet and injected through the raw device.

With PingClient/PingServer packet disguise, use these edge orders:

```text
TunDevice -> PingClient -> IpOverrider -> RawSocket
RawSocket -> IpOverrider -> PingServer -> TunDevice
```

Ping6Client/Ping6Server use the same edge orders with outer IPv4 Protocol `58` in direct mode or `41` in `ipv6-in-ipv4` mode. Select `capture-protocols: [58]` or `[41]` respectively with the peer's outer source range. New-mode TunDevice MTU is at most 1451 at a 1500-byte path, before any other expansion; reassemble native/outer IPv4 fragments before Ping6. Inner IPv6 Fragment headers are rejected by Ping6.

In first position, RawSocket forwards captured carrier packets upstream into
PingServer. PingServer restores the inner packet toward TunDevice; only with
its `send-replies: true` setting does it first send an exact type-0 Echo Reply
back toward RawSocket. Reply generation defaults to false on both Ping nodes
and can be enabled independently. Plain packets from TunDevice return downstream
as fresh type-8 Echo Requests for raw injection; they are not inserted into an
unrelated Echo Reply.

## Minimal practical example

Node fragment; define the referenced neighbors and peers in the same deployment.

Replace the capture addresses with the intended peer addresses and define `next-node-name` as the packet path. This fragment preserves fragments; use reassembly for consumers that require complete packets, including Ping/Ping6. Capture and raw injection require the platform support and privileges described below.

```json
{
  "name": "raw-ip",
  "type": "RawSocket",
  "settings": {
    "fragment-policy": "preserve-fragments",
    "capture-device-name": "capture-in",
    "raw-device-name": "raw-out",
    "capture-filter-mode": "source-ip",
    "capture-ips": [
      "192.0.2.10",
      "198.51.100.0/24"
    ]
  },
  "next": "next-node-name"
}
```

See [Configuration](#configuration) for defaults and conditional requirements and [Usage and troubleshooting](#usage-and-troubleshooting) for complete examples and operational limits.

## Configuration

### Required JSON Fields

#### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"RawSocket"`.

### Optional `settings` Fields

- `opaque-flow-mode` `(string)`
  Opaque IPv4 receive policy: `prefix` (default), `peer`, `spread`, or `auto`.
  See the detailed `opaque-flow-mode` section below for selection and limitations.

- `capture-ips` or `capture-ip` `(string or array of strings)`
  Equivalent names for the IPv4 addresses or IPv4 CIDR ranges used by the capture device filter. Either key accepts one string or an array, and every array element becomes a capture range. `listen-ips` remains accepted as a compatibility alias with the same input shapes.

  Each value may be a single IPv4 address such as `"192.0.2.10"` or a CIDR range such as `"198.51.100.0/24"`. IPv6 entries are rejected. If no capture key is present, or the selected key contains an empty array, capture is disabled and `RawSocket` starts only its raw output device.

- `dont-capture-protocols` `(array of integers)`
  IPv4 Protocol identifiers to leave out of capture, such as `1` for ICMP,
  `6` for TCP, or `17` for UDP. Entries must be integers from `0` through `255`;
  duplicates are ignored. Zero is the literal protocol byte, not “all protocols.”

  Default: `[]` (also used when omitted)

  Excluded incoming packets skip this node's capture rules and continue through
  normal host conntrack and firewall processing. This setting does not restrict
  raw output: packets sent by WaterWall's raw socket still bypass conntrack.

  For example, these settings leave incoming ICMP and TCP to the host:

  ```json
  { "dont-capture-protocols": [1, 6] }
  ```

- `capture-protocols` `(array of integers)`
  Capture only the literal IPv4 Protocol bytes listed here, for example `[6]`
  for fake-TCP carriers on both peers. Entries must be whole numbers
  from `0` through `255`; duplicates are ignored. Omission preserves the default
  of all protocols. An explicit empty array captures none. This setting and
  `dont-capture-protocols` are mutually exclusive, even for empty lists.

  The allowlist is compiled once into the existing protocol predicate: Linux
  uses fixed-size cBPF on every NFQUEUE rule; Windows uses
  WinDivert. Unselected protocols stay in the host stack and retain normal
  conntrack/firewall processing. Raw output is unaffected. Nonempty exclusions,
  including those produced from this allowlist, require Linux's iptables `bpf`
  match. Source-IP capture ranges still apply.

  For example, a fake-TCP client captures TCP from its server with:

  ```json
  {
    "capture-filter-mode": "source-ip",
    "capture-ips": ["198.51.100.10"],
    "capture-protocols": [6]
  }
  ```

  At the server, use the client's source address instead. This captures **all
  TCP from the selected source addresses**, including ordinary SSH or HTTPS
  between those endpoints, regardless of port. FakeTcpHeader checks its carrier
  ports only after capture; rejecting a packet cannot return it to the host
  stack. IP/protocol filtering is not authentication. See
  [FakeTcpHeaderClient](../FakeTcpHeaderClient/description.md) and
  [FakeTcpHeaderServer](../FakeTcpHeaderServer/description.md) for the carrier
  ports and envelope.

- `capture-filter-mode` `(string)`
  Filter mode for captured traffic. This field is required when at least one capture range is configured and is ignored in write-only mode.

  Parsed values are:
  - `"source-ip"`
  - `"dest-ip"`

  The current implementation only accepts `"source-ip"`. If `"dest-ip"` is selected, tunnel creation fails with a message telling you to use `TunDevice` for outgoing capture instead.

- `skip-sysctl` `(boolean)`
  On Linux, skip Capture's best-effort `sysctl` performance tuning. NFQUEUE socket configuration and the iptables rules required to direct packets into NFQUEUE still run.

  Default: `false`

- `multi-queue` `(boolean)`
  On Linux, attempt one receive queue per event worker. If additional queues or
  steering are unavailable, use one receive queue owned by worker 0. Setting
  this to `false` selects that single-queue path directly. Packet processing
  still uses all configured workers. Linux receive uses event workers in both
  modes, with no dedicated capture reader thread. Windows accepts the setting
  and keeps its existing receive arrangement. Write-only mode has no receive queues.

  Default: `true`

- `kernel-queue-tune` `(boolean)`
  Tune Linux capture kernel queues at startup. Default: `true` on Linux,
  `false` elsewhere. `false` retains the baseline NFQUEUE and receive-buffer
  setup and still logs the kernel settings. Valid values have no effect on
  other platforms or in write-only mode. This setting is independent of
  `skip-sysctl` and core `misc.tcp-tune`.

- `kernel-queue-packets` `(integer)`
  Requested NFQUEUE packet allowance **across this capture device**, divided
  over its final active receive queues. Omit it for automatic sizing.

- `kernel-receive-buffer` `(integer)`
  Requested Netlink receive buffering in bytes **across this capture device**,
  divided over its final active receive sockets. Omit it for automatic sizing.
  This is the `SO_RCVBUF` request scale, before Linux's doubled accounting.

  Both numeric settings require whole numbers in `1..2147483647` (`INT_MAX`).
  Zero, negative or fractional numbers, strings, booleans and `null` are rejected;
  automatic sizing is selected only by omission. Overrides replace automatic
  targets but never reduce the baseline or a larger current allowance. They are
  applied only with `kernel-queue-tune` enabled. All three settings are validated
  even when tuning is disabled, capture is disabled or the platform is not Linux.

- `capture-device-name` `(string)`
  User-visible or internal name for the capture device.

  Default: `"unnamed-capture-device"`

- `raw-device-name` `(string)`
  User-visible or internal name for the raw output device.

  Default: `"unnamed-raw-device"`

- `mark` `(integer)`
  Optional Linux output socket mark, an integer from `1` through `4294967295`.
  It must be dedicated to WaterWall traffic: the output NOTRACK exemption matches
  this exact mark, so unrelated traffic sharing it would also bypass conntrack.
  Zero, negative, fractional and nonnumeric values are rejected. An explicit mark
  is preserved exactly for routing and NOTRACK, including across device restarts.

  When omitted, WaterWall selects an automatic mark on each start using the
  collision checks described below. WinDivert does not apply Linux socket marks.

  For explicit policy routing, use:

  ```json
  "settings": {
    "fragment-policy": "preserve-fragments", "mark": 10 }
  ```

### Packet receive policies

#### `opaque-flow-mode` (optional, default: `prefix`)

Accepts only the exact strings `prefix`, `peer`, `spread` and `auto`. Empty or
unknown strings, `null` and other JSON types fail construction on every platform,
including write-only RawSocket. Omission always selects `prefix`, even beside Ping or Ping6.
The setting is independent of `multi-queue`, `gso` and `fragment-policy`; a single
receive queue still dispatches over the configured processing workers.

For structurally valid, unfragmented IPv4 with Protocol other than TCP (6) or
UDP (17):

| Value | Receive worker selection |
| --- | --- |
| `prefix` | Symmetric hash of addresses, protocol and the first four IP-payload bytes as two big-endian 16-bit endpoint fields. |
| `peer` | Hash addresses and protocol only; ignore every payload byte. |
| `spread` | Spread packets using the backend's existing mechanism. |
| `auto` | Resolve once at startup using the exact direct Ping or Ping6 decoding neighbour below; otherwise use `prefix`. |

The prefix begins after the actual IPv4 header, including options, and must fit
inside the declared total length. Fewer than four payload bytes use the same
address/protocol fallback as `peer`. Native TCP/UDP always uses the shared 32-bit
address/port/protocol worker hash when four transport bytes are present, and the
address/protocol fallback otherwise; opaque mode never validates transport flags,
length fields or checksums. IPv6 parsing boundaries and fragment policy are unchanged.

`prefix` keeps a visible flow together only while those four bytes stay stable.
A fixed XOR can preserve that property; arbitrary encryption or changing masks
need not. `peer` deliberately groups every opaque packet with the same address
pair and protocol, concentrating unrelated hidden flows on one worker. `spread`
can process those flows in parallel but can reorder packets before a consumer
sees them. A downstream stateful consumer still chooses its owner from the tuple
it actually consumes after decoding or rewriting.

Only requested `auto` inspects finalized topology before device construction or
capture activation. Upstream receive publication toward `next` selects `peer`
only for the immediate physical node of exact type `PingServer` or `Ping6Server`; downstream
publication toward `prev` selects `peer` only for exact type `PingClient` or `Ping6Client`.
Encoding directions, intervening nodes, wrappers and all other layouts select
`prefix`. Instance names do not participate. Explicit modes always take precedence;
an opposite RawSocket never implies `spread`. With both devices using `auto`:

```text
TunDevice -> PingClient -> RawSocket
  prefix                     peer

RawSocket -> PingServer -> TunDevice
   peer                     prefix
```

The resolved mode is fixed per device generation, including single-queue fallback
and restart; readers do not inspect traffic or reevaluate topology per packet.
Ping and Ping6 pass unrelated packets through, so automatic `peer` groups unrelated
opaque traffic as well; mixed traffic may require an explicit setting. Startup
logs requested mode, effective mode, selection reason and effective queue count.

#### `fragment-policy` (optional, default: `reassemble`)

Omitting this setting selects `reassemble`: IPv4 fragments are assembled before
publication into the chain. `preserve-fragments` keeps their bytes and boundaries.
The policy does not impose a node-name or topology allowlist; ordinary layer and
chain validation still applies. Invalid values (including `null`) fail startup.

`PacketsToConnection` upstream packet input and `ConnectionToPackets` downstream
packet input require complete IPv4 datagrams. Either input drops unsupported
fragments before stack delivery, logs the first drop as a warning, and counts
later drops without terminating the process. Reassemble before these consumers,
regardless of the device policy or intervening nodes. DF alone is not a fragment;
MF or a nonzero fragment offset is.

Reassembly emits complete IPv4 datagrams up to 65,535 bytes. It does not raise
packet-output limits or device MTU, and does not automatically fragment output
again. See Developer Guide Part 4 for assembly bounds and packet ownership.

### Linux kernel receive queue sizing

Kernel queue sizing uses the final active receive queue count after any fallback.
The baseline device-wide allowances are 65,536 NFQUEUE packets and 64 MiB of
requested Netlink receive buffering. Automatic tuning starts from those totals
and uses these preferred per-queue targets:

| Configured RAM profile | Preferred packets per queue | Preferred receive-buffer request per socket |
| --- | ---: | ---: |
| S1 / S2 | 1,024 | 1 MiB |
| M1 / M2 (`client` / `client-larger`) | 2,048 | 2 MiB |
| L1 / L2 (`server`) | 4,096 | 4 MiB |

For each resource, the automatic per-queue target is the larger of its baseline
share and its preferred target, with the preferred target capped by the share of
131,072 packets or 128 MiB, respectively. Division uses the actual queue count.
These caps constrain automatic targets, not larger existing values or explicit
overrides. An explicit total replaces the corresponding automatic target and is
divided over the active queue set, while preserving at least the baseline share.
With tuning disabled, baseline setup still runs; the overrides do not apply.

The profiles are configured memory policy, not detected host RAM. Allowances
apply separately to each capture device, so multiple devices add their budgets.
These numbers are not actual RSS or packet-payload byte limits. Linux reports
`SO_RCVBUF` using doubled bookkeeping values, and host socket limits can cap the
accepted request. If an effective increase cannot be confirmed, tuning preserves
the existing buffer. Increasing a queue can absorb bursts at
the cost of extra memory and latency; it is not a throughput guarantee.

Startup logs the active queue count and target source (`auto`, `override` or
`disabled`), each NFQUEUE limit confirmed by a kernel ACK, and requested/read-back
`SO_RCVBUF`. An unconfirmed limit is reported as unknown. These logs remain
enabled when tuning is disabled. Refused tuning or unavailable readback produces
a warning and keeps usable capture queues running.

This tuning does not change the shared userspace receive FIFO, callback batch
sizes or raw output backlog. It introduces no global sysctl writes and is
independent of `skip-sysctl` and core `misc.tcp-tune`.

### Capture filter behavior

The capture device is configured from the ranges supplied through either `capture-ips` or `capture-ip`. Captured packets matching the configured source IP and protocol filters are dropped from the host kernel networking stack: normal local transport delivery stops while capture is active, and WaterWall processes its captured copy.

Current implementation behavior:

- on Windows, the capture filter combines `ip.SrcAddr` equality or inclusive range checks with exclusions on `ip.Protocol`
- on Linux, multiqueue capture creates a flow rule per queue and range; only `spread` adds random opaque rules. Single-queue capture creates one queue rule per range
- `capture-filter-mode` is parsed, but only the `source-ip` path is currently implemented

On Linux, nonempty protocol exclusions, whether configured directly or derived
from `capture-protocols`, require the iptables `bpf` match (`xt_bpf`). One
fixed-size classic BPF predicate checks the IPv4 Protocol byte in every
NFQUEUE rule. It also handles fragments and protocol zero
without interpreting transport headers. Insertion, rollback and deletion use
identical predicates. Missing matcher support fails startup and rolls back
installed rules. An unrestricted protocol selection adds no protocol matcher.
Windows applies the same protocol selection in its WinDivert filter.

By default the Linux capture backend applies best-effort `sysctl` tuning for
backlogs and other TCP parameters before creating NFQUEUE resources. The core
`misc.tcp-tune` setting controls separate `net.ipv4.tcp_mem` tuning when
`misc.splice` is also enabled. `"skip-sysctl": true` suppresses
only Capture's sysctl tuning batch. Per-device `kernel-queue-tune`, the netlink
operations and iptables commands needed to configure NFQUEUE remain independent.

Linux capture installs
NFQUEUE rules in `raw PREROUTING`, matching each source range and its protocol
filters with `--dst-type LOCAL`. This captures local-unicast destinations only;
ordinary transit traffic, broadcasts and multicast remain in the host stack.
Active capture returns `NF_DROP` before conntrack, DNAT and the normal routing
decision, then dispatches the captured copy. Selected input does not traverse
later host firewall hooks. No incoming NOTRACK rules are installed.

The rules use normal raw-table priority, leaving fragment reassembly ordering and
the 1,500-byte capture limit unchanged. They do not change interface MTU or provide
PMTU discovery; necessary ICMP errors still need to reach the responsible stack.
`skip-sysctl` does not disable queue-rule setup.

The coordinator services prepared inactive queues with `NF_ACCEPT` during rule
installation. Capture activates once all selected queue rules are installed.
If multiqueue installation fails, WaterWall removes the partial rules and retries
one receive queue. Failed single-queue installation or incomplete rollback fails
startup. Cleanup tracks failed or outcome-unknown queue commands against the
raw PREROUTING chain, retaining ownership for retry. Reader failure requests
orderly shutdown, whose lifecycle owner performs rule cleanup.

On Linux, the NFQUEUE rules use `--queue-bypass`. If WaterWall is not listening
on the queue, matching packets continue through the host firewall instead of
being dropped by an absent queue. Acceptance resumes at later tables; subsequent
rules in the queued table are skipped. With early capture, accepted input can
undergo normal conntrack processing. This is a fail-open availability policy:
packets are not captured or transformed while no listener exists. It does not
make queue overflow fail-open while WaterWall remains bound to the queue.
WaterWall avoids queue numbers already referenced by either filter INPUT or
raw PREROUTING rules. A
failed startup closes its queues; complete rollback permits a later restart.
Unresolved rule cleanup or an inactive queue I/O failure makes that capture-device
object non-restartable. Closing the queues activates `--queue-bypass` for any
NFQUEUE rule that could not be removed. Before capture activation and
after worker detachment, the coordinator performs bounded nonblocking
`NF_ACCEPT` drains during rule insertion, rollback, and bring-down cleanup.
The raw output device is ready before capture activates. Receive activation is
queued behind packet Init on each owner worker. During later startup commands,
capture uses `NF_DROP` and queues packets for worker delivery within the same
shared budget; a full session FIFO stops native reads. Packets may remain in the
bounded kernel queues and session FIFO until worker loops dispatch. Active workers
use drop-and-dispatch. Shutdown deactivates capture, closes receive admission,
and detaches each watcher on its owner before rule cleanup and descriptor release.
A terminal receive failure closes receive admission and requests orderly cleanup;
closed queue sockets make any residual rules fail open. No dedicated Linux
capture reader or cleanup thread is created.

## Usage and troubleshooting

### Configuration Example

```json
{
  "name": "raw-ip",
  "type": "RawSocket",
  "settings": {
    "fragment-policy": "preserve-fragments",
    "capture-device-name": "capture-in",
    "raw-device-name": "raw-out",
    "capture-filter-mode": "source-ip",
    "capture-ips": [
      "192.0.2.10",
      "198.51.100.0/24"
    ]
  },
  "next": "next-node-name"
}
```

For write-only packet injection, omit all capture-range keys:

```json
{
  "name": "raw-output",
  "type": "RawSocket",
  "settings": {
    "fragment-policy": "preserve-fragments",
    "raw-device-name": "raw-out"
  }
}
```

### Notes And Caveats

- The current receive path only forwards IPv4 packets.
- `capture-filter-mode` is effectively limited to `"source-ip"` when capture is enabled.
- Omitting capture ranges intentionally selects write-only raw packet injection.
- Platform support depends on the raw/capture backend available on the operating system.

### Why `TunDevice` may be a better fit for some cases

The current `RawSocket` implementation is focused on capturing inbound IPv4 traffic that matches a source-IP filter and injecting raw IPv4 packets.

If you need a virtual interface model or packet handling that is closer to routed interface traffic, `TunDevice` is usually the better match.

## Implementation details

### Detailed Behavior

#### Capture path

During `onStart`, `RawSocket`:

- when at least one capture range is configured, decides which adjacent tunnel should receive captured packets and creates the capture device
- creates the raw output device
- brings the raw output device up before activating capture rules

With no configured capture range, no capture device, NFQUEUE socket, capture reader, or capture rule is created. Only the raw output device is started.

Linux assigns each receive queue to exactly one worker and performs bounded,
nonblocking reads on that worker's event loop. Reads collect up to 256 available
packets with `recvmmsg()`, using reusable buffers and no timer to fill a batch.
Prepared buffer storage is bounded across the device, so a large receive queue
count can reduce this maximum. Supported kernels receive one cumulative verdict
for each same-verdict prefix with consecutive packet IDs; an acknowledged startup
probe selects explicit per-packet `sendmmsg()` verdicts when cumulative verdicts
are unavailable. Packet-ID gaps also select explicit verdicts.
Only packets whose DROP verdict was sent enter the tunnel chain. Partial sends,
FIFO pressure and processing limits retain the remaining packets in order and
resume them on the owning worker. Queue count, steering and the
resolved opaque mode stay fixed while capture is active. Native IPv4 TCP/UDP
uses the same symmetric 32-bit address/port/protocol worker hash as TUN and
consumer affinity. Opaque IPv4 follows `opaque-flow-mode`, defaulting to `prefix`.
With multiple queues, complete packets continue on the receiving worker. With one
queue, software applies the effective mode before worker FIFO admission. Windows
capture uses the same software policy. Consumers still establish ownership after
decoding or rewriting their tuple.

Only `spread` installs random opaque NFQUEUE rules (`statistic --mode random`).
Cascading probabilities give queues approximately the same share; exact counts
and packet order are not guaranteed. Its single-reader software path retains the
session-local cursor. Deterministic modes route opaque packets through the flow
predicates and install no random opaque rules.

All IPv4 fragments, including fragment zero, retain address/protocol kernel
steering. The shared fragment table keeps its existing staging and fragment-zero
classification, using the common worker hash separately from the retained full64
consistency fingerprint. Reassembly stays on its reader worker with multiple
queues and follows the effective complete-packet policy with one reader.
Fragmented and ordinary packets from the same flow may have different workers.
Protocol exclusions apply equally to every rule family. Queue predicates require
the iptables `bpf` match; only spread's opaque rules require `statistic`. Failed
multiqueue setup falls back to one receive queue after complete owned-rule cleanup.

When a packet is captured:

- the packet is checked for IP version
- Linux capture requires complete IPv4 with a bounded header length and a total length matching the captured bytes.
  It preserves invalid checksums and opaque transport bytes, including XORed headers, unusual TCP flags, invalid TCP
  data offsets, and inconsistent UDP lengths. It retains Netlink message safety checks, actual truncation detection,
  and the 1,500-byte capture limit
- Linux only attempts checksum completion when `NFQA_SKB_INFO` explicitly sets `NFQA_SKB_CSUMNOTREADY` on an
  unfragmented packet. If its headers cannot be interpreted safely, the bytes remain unchanged and capture still
  admits the packet. An invalid checksum without pending-offload metadata never causes repair or rejection
- Windows retains WinDivert checksum/direction provenance handling: explicitly pending offload is materialized when
  possible, while untrusted corrupt checksums and fragmented transport offload are rejected
- Windows capture also retains the 1,500-byte limit. A larger packet reported by WinDivert as
  `ERROR_INSUFFICIENT_BUFFER` is discarded with a rate-limited warning; reading continues and the device stays up.
  Truncated bytes are never forwarded. Other terminal receive errors still fail the device.
- fragmented packets are never given a transport checksum calculated over one fragment. Linux passes their bytes
  unchanged to the existing fragment-affinity validation, which may reject them
- only IPv4 packets are currently forwarded by this path
- matching packets are intercepted and dropped from the host kernel stack (using drop-and-dispatch verdicts or packet diversion), preventing normal local transport delivery while WaterWall processes its captured copy
- the packet is forwarded through the chosen adjacent side using the worker packet line

The reader's fragment policy determines publication: `reassemble` holds fragment
bytes until a complete datagram can be delivered, while `preserve-fragments`
retains fragment boundaries and worker affinity. Published buffers follow ordinary
ownership through copies, delays and worker handoff; they carry no fragment
settlement claim. Local-stack packet inputs enforce their complete-datagram
requirement at delivery. See the fragment-policy section below.

#### Output path

When payload reaches `RawSocket` from upstream or downstream:

- the payload is treated as a raw IP packet
- the complete packet is structurally validated as exact IPv4, even when no
  checksum recalculation was requested; trailing bytes and malformed or
  truncated packets are dropped
- checksum recalculation is performed if requested by the packet buffer
- the packet is written through the raw device

Both upstream and downstream payload handlers write to the same raw output device.

Output is queued on the submitting event worker and flushed later on that same
worker. Each worker keeps its own FIFO and recycles completed buffers through its
existing pool. There is no dedicated raw writer thread or writer pool, and no
application mutex serializes native writes across workers. Device-wide limits
remain 131,072 packets on Linux and 256 on Windows, including queued and active
output. Each worker preserves its FIFO order; independent workers have no total
output order.

Linux flushes use up to 512 original packets in one nonblocking `sendmmsg()` call.
A partial send retires only the sent prefix and retains the unsent suffix ahead
of newer packets. `EINTR` yields to another deferred attempt. After `EAGAIN`, a
1 ms worker retry checks writability with a zero-timeout `poll()`; it never waits
inside the event worker. Resource-pressure and packet/destination errors retain
the existing one-packet discard policy; permanent descriptor failures request
shutdown. No timer waits for a batch to fill.

Windows uses overlapped WinDivert output. A pending operation retains its original
packet until completion; the native completion notification schedules owner-worker
work and never borrows a worker pool. Stop closes admission, quiesces notifications,
cancels pending writes, and waits for completion before releasing retained packets.

On Linux, raw output always bypasses conntrack and requires `iptables` and
permission to manage firewall rules (`CAP_NET_ADMIN`). Before enabling the
writer, WaterWall sets `SO_MARK` and installs an exact-mark NOTRACK rule in
`raw OUTPUT`. An explicit `mark` is used unchanged for both operations and must
be dedicated to WaterWall; other traffic using the same mark would also bypass
conntrack. Without `mark`, WaterWall reads IPv4 firewall and routing snapshots
and selects a random mark on each start. Automatic selection additionally
requires `iptables-save` and `ip` from iproute2. Failure to select or apply the
mark, inspect required policy, or install the rule fails startup and attempts
cleanup.

Automatic selection prefers `0x80000000..0xffffffff`, falls back below that range when
necessary, and avoids values below `0x00010000`. It checks mark comparisons and
literal mark assignments exposed by `iptables-save`, plus `ip -4 rule show`,
including masks and the match results that an unmarked packet would have had.
The selected mark is logged. This is best-effort collision avoidance, not a
system-wide reservation: native nftables rules, tc/eBPF policy, marks on other
sockets, concurrent changes, and future programs may not be visible to it.

The exemption avoids conntrack; ordinary routing and firewall processing still
apply. Exempted output cannot rely on host conntrack-based NAT or stateful
filtering. Normal raw-table priority, fragment handling, and MTU limits remain
unchanged. Other administrators' rules remain independent.

Output admission closes and admitted native writes finish before the
`WWRAW_NOTRACK_...` rule is removed. Queued output is discarded during stop;
a delayed callback from an old generation cannot write into a restarted device.
Startup rollback and destruction retry pending cleanup, including commands with
uncertain outcomes. Abrupt process death or persistent command failures can
leave this exact-mark rule in `raw OUTPUT`; remove the rule identified by its
logged comment if cleanup cannot complete.

#### Checksum behavior

Before writing a packet, `RawSocket` checks the packet buffer request:

- if `sbufGetRecalculateChecksum(buf)` is true, checksums are recomputed
- full packet checksum recalculation is attempted
- for fragmented IPv4 packets, transport checksum recalculation is skipped automatically and only the IPv4 header checksum is recomputed

#### Callback and line lifecycle

Payload is the meaningful callback path. Ordinary connection lifecycle
callbacks (`Init`, `Est`, `Pause`, and `Resume`) are terminal absorbers at this
packet adapter. An unexpected `Finish` in either direction is a fatal packet-line
lifecycle violation and aborts the program; it is not a no-op.

The chain owns one persistent packet line per worker. `RawSocket` never destroys
those lines and has zero bytes of line state.

### Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainHead` &#124; `kNodeFlagChainEnd` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` |
| `layer_group_prev_node` | `kNodeLayer3` |
| `layer_group_next_node` | `kNodeLayer3` |
| `required_padding_left` | `0` bytes |
