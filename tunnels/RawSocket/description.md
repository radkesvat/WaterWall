<!--
Documentation version: 160
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/RawSocket.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/RawSocket.mdx, and all files must keep the same documentation version.
-->

# RawSocket Node

`RawSocket` connects WaterWall to raw IPv4 packet capture and raw packet injection. When capture ranges are configured, it captures matching IP packets from the host networking stack and forwards them into the chain. Independently, it can inject raw IP packets coming from the chain back into the system.

This node is a layer-3 adapter rather than a connection-oriented tunnel.

## What It Does

- Optionally creates a capture device for matching IPv4 packets.
- Creates a raw output device for sending raw IPv4 packets.
- When capture is enabled, captures packets that match the configured IP and protocol filters and drops them from the host kernel network stack so only WaterWall receives and accesses them.
- Forwards captured packets to the adjacent chain side.
- Writes raw IP packets from the chain out through the raw device.
- Applies checksum recalculation before writing when the packet buffer requests it.
- Bypasses Linux conntrack by default for capture ranges and raw output; output uses an automatically selected socket mark.

## Typical Placement

`RawSocket` can be placed at either edge of a chain:

- if it is last in the chain, captured packets are forwarded to the previous node
- otherwise, captured packets are forwarded to the next node

Payload reaching `RawSocket` from upstream or downstream is treated as an IP packet and injected through the raw device.

With PingClient/PingServer packet disguise, use these edge orders:

```text
TunDevice -> PingClient -> RawSocket
RawSocket -> PingServer -> TunDevice
```

In first position, RawSocket forwards captured carrier packets upstream into
PingServer. PingServer restores the inner packet toward TunDevice; only with
its `send-replies: true` setting does it first send an exact type-0 Echo Reply
back toward RawSocket. Reply generation defaults to false on both Ping nodes
and can be enabled independently. Plain packets from TunDevice return downstream
as fresh type-8 Echo Requests for raw injection; they are not inserted into an
unrelated Echo Reply.

## Configuration Example

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
    ],
    "bypass-conntrack": true
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
    "raw-device-name": "raw-out",
    "bypass-conntrack": true
  }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"RawSocket"`.

## Optional `settings` Fields

- `capture-ips` or `capture-ip` `(string or array of strings)`
  Equivalent names for the IPv4 addresses or IPv4 CIDR ranges used by the capture device filter. Either key accepts one string or an array, and every array element becomes a capture range. `listen-ips` remains accepted as a compatibility alias with the same input shapes.

  Each value may be a single IPv4 address such as `"192.0.2.10"` or a CIDR range such as `"198.51.100.0/24"`. IPv6 entries are rejected. If no capture key is present, or the selected key contains an empty array, capture is disabled and `RawSocket` starts only its raw output device.

- `dont-capture-protocols` `(array of integers)`
  IPv4 Protocol identifiers to leave out of capture, such as `1` for ICMP,
  `6` for TCP, or `17` for UDP. Entries must be integers from `0` through `255`;
  duplicates are ignored. Zero is the literal protocol byte, not “all protocols.”

  Default: `[]` (also used when omitted)

  Excluded incoming packets skip this node's capture and incoming NOTRACK rules,
  including when `bypass-conntrack` is enabled. They continue through normal host
  conntrack and firewall processing. This setting does not restrict raw output:
  packets sent by WaterWall's raw socket still follow `bypass-conntrack`.

  For example, these settings leave incoming ICMP and TCP to the host:

  ```json
  { "dont-capture-protocols": [1, 6] }
  ```

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

- `opaque-flow-affinity` `(boolean)`
  Keep each opaque flow (complete IPv4 that is neither TCP nor UDP, keyed by its
  address pair and protocol) on one worker instead of spreading its packets
  across workers. With multiple receive queues, opaque packets join the
  address/protocol flow lanes and the random opaque rules are not installed;
  with one reader, they take the flow-hash worker instead of the rotation.

  Enable it when the captured protocol is itself a tunnel carrying TCP, such as
  `PingClient`/`PingServer` over ICMP. That stream is one opaque flow; spread
  over several workers, its packets leave the chain out of order and the inner
  TCP connections slow down. Opaque traffic between different hosts still
  spreads across workers. Default: `false`

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

- `bypass-conntrack` `(boolean)`
  On Linux, control conntrack bypass for both configured capture ranges and this
  node's raw output socket. When enabled, WaterWall installs source-range NOTRACK
  rules in `raw PREROUTING` and an exact-mark rule in `raw OUTPUT` using an
  automatically selected socket mark. In write-only mode, only the output rule
  is needed. Setting this to `false` installs neither kind of NOTRACK rule;
  NFQUEUE capture and drop-and-dispatch remain active. The setting has no effect
  on the Windows WinDivert backend.

  Default: `true`

- `mark` `(integer)`
  Explicit firewall mark for the raw output device where supported. This field
  is permitted only with `"bypass-conntrack": false`; even an explicit `0` is
  rejected while bypass is enabled. With bypass disabled, WaterWall installs no
  capture or output NOTRACK rules and preserves the configured mark.

  Default when bypass is disabled: `0`

  For explicit policy routing, use:

  ```json
  "settings": {
    "fragment-policy": "preserve-fragments", "bypass-conntrack": false, "mark": 10 }
  ```

## Detailed Behavior

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

### Capture path

During `onStart`, `RawSocket`:

- when at least one capture range is configured, decides which adjacent tunnel should receive captured packets and creates the capture device
- creates the raw output device
- brings the raw output device up before activating capture rules

With no configured capture range, no capture device, NFQUEUE socket, capture reader, or capture rule is created. Only the raw output device is started.

Linux assigns each receive queue to exactly one worker and performs bounded,
nonblocking reads on that worker's event loop. Queue count and steering stay fixed
while capture is active. Complete TCP/UDP packets use symmetric IPv4 address,
protocol, and port receive steering. With multiple queues, complete packets
continue on the receiving worker; consumers establish any required flow ownership
after transformations rather than relying on capture to select their owner.
A ported protocol is a protocol number that its chain declares as beginning with a
TCP/UDP-style port pair: the replacement numbers of an `IpManipulator`
`protoswap-tcp` or `protoswap-udp` in the same chain, which leave the transport
header at the start of the payload. `RawSocket` reads the chain's declarations when
it starts and logs the protocols it steers. These packets use the same symmetric
port receive steering as TCP/UDP, so one inner flow keeps one queue and one worker,
in order, while different flows spread over the queues. The hash only combines the
two port words symmetrically, so a constant byte-wise obfuscation of the header
(for example an XOR) does not change which packets agree. A packet shorter than the
port pair falls back to address and protocol steering. A chain supports at most two
ported protocols; a further declared number is refused with a warning and stays
opaque. A protocol that no node of this chain declares stays opaque however another
chain uses it, so a relay that only forwards someone else's swapped traffic keeps
per-packet distribution and may still reorder it. Only IPv4 is captured and swapped.

Other complete IPv4 protocols use random kernel queue selection
(`statistic --mode random`) and continue on the receiving worker. Cascading
conditional probabilities give each queue approximately the same share; exact
counts and packet order are not guaranteed. This removes the shared nth-selection
counter without claiming that every kernel RNG implementation is lock-free.
With one receive queue, complete native TCP/UDP and ported-protocol packets with
visible ports use the symmetric flow hash, keeping ordered packets of one flow on
one worker FIFO. Opaque or unclassifiable packets use a session-local round-robin
sequence across workers. Windows capture applies the same policy to native TCP/UDP
and treats every other protocol as opaque, declared or not. Protocol-50 traffic
between one IP pair that is not a declared protocol swap therefore remains
parallel; no transport ports are guessed for it. Each NFQUEUE has its share of the
kernel queue budget, so a heavy flow that fills its queue drops there first.

Every IPv4 fragment, including fragment zero, retains address/protocol receive
steering and the shared fragment table's existing staging and ownership rules.
Completed reassembly follows the ordinary complete-packet distribution policy.
Protocol exclusions apply equally to both rule sets. Queue predicates use the
iptables `bpf` match; opaque multiqueue routing also requires `statistic`. If
multiqueue setup fails, capture falls back to one receive queue. The number of
predicates examined grows with queue count.

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

### Output path

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

On Linux, output bypass requires `iptables`, `iptables-save`, `ip` from
iproute2, and permission to manage firewall rules (`CAP_NET_ADMIN`). Before
enabling the writer, WaterWall checks IPv4 firewall and routing
snapshots, selects a random mark, sets `SO_MARK`, and inserts its NOTRACK rule.
Failure to inspect policy, find a suitable mark, set the socket mark, or install
the rule fails startup and attempts cleanup.

Selection prefers `0x80000000..0xffffffff`, falls back below that range when
necessary, and avoids values below `0x00010000`. It checks mark comparisons and
literal mark assignments exposed by `iptables-save`, plus `ip -4 rule show`,
including masks and the match results that an unmarked packet would have had.
The selected mark is logged. This is best-effort collision avoidance, not a
system-wide reservation: native nftables rules, tc/eBPF policy, marks on other
sockets, concurrent changes, and future programs may not be visible to it.

The exemption avoids conntrack; ordinary routing and firewall processing still
apply. Exempted output cannot rely on host conntrack-based NAT or stateful
filtering. Normal raw-table priority, fragment handling, and MTU limits remain
unchanged. `bypass-conntrack=false` disables this node's capture and output
exemptions; other administrators' rules remain independent.

Output admission closes and admitted native writes finish before the
`WWRAW_NOTRACK_...` rule is removed. Queued output is discarded during stop;
a delayed callback from an old generation cannot write into a restarted device.
Startup rollback and destruction retry pending cleanup, including commands with
uncertain outcomes. Abrupt process death or persistent command failures can
leave this exact-mark rule in `raw OUTPUT`; remove the rule identified by its
logged comment if cleanup cannot complete.

### Capture filter behavior

The capture device is configured from the ranges supplied through either `capture-ips` or `capture-ip`. Captured packets matching the configured source IP and protocol filters are dropped from the host kernel networking stack: normal local transport delivery stops while capture is active, and WaterWall processes its captured copy.

Current implementation behavior:

- on Windows, the capture filter combines `ip.SrcAddr` equality or inclusive range checks with exclusions on `ip.Protocol`
- on Linux, multiqueue capture creates a flow rule and an opaque-protocol rule per receive queue for each configured IPv4 address or CIDR range; single-queue capture creates one queue rule per range
- `capture-filter-mode` is parsed, but only the `source-ip` path is currently implemented

On Linux, a nonempty `dont-capture-protocols` list requires the iptables `bpf`
match (`xt_bpf`). One fixed-size classic BPF predicate checks the IPv4 Protocol
byte in both the NFQUEUE and incoming NOTRACK rules. It also handles fragments
and protocol zero without interpreting transport headers. Missing matcher
support fails startup and rolls back installed rules. An empty list adds no
protocol matcher. Windows applies the same exclusions in its WinDivert filter.

By default the Linux capture backend applies best-effort `sysctl` tuning for
backlogs and other TCP parameters before creating NFQUEUE resources. The core
`misc.tcp-tune` setting owns writes to `net.core.rmem_max`, `net.core.wmem_max`,
`net.ipv4.tcp_rmem`, and `net.ipv4.tcp_wmem`. `"skip-sysctl": true` suppresses
only Capture's sysctl tuning batch. Per-device `kernel-queue-tune`, the netlink
operations and iptables commands needed to configure NFQUEUE remain independent.

When `bypass-conntrack` is enabled (the default), Linux capture installs a
matching `CT --notrack` rule in `raw PREROUTING` for each capture source range, with the same protocol exclusions as capture.
The exemption also requires `--dst-type LOCAL`: it covers packets addressed to a local unicast address,
without exempting ordinary transit traffic, broadcasts, or multicast. The INPUT
capture rule checks the source range and protocol exclusions without this
destination-type restriction. Raw-table matching is before DNAT, so exempted
traffic cannot rely on this host's conntrack-based NAT
or stateful firewall handling. Setting `bypass-conntrack=false` disables these
capture exemptions along with the output exemption. NFQUEUE capture continues
with its existing drop-and-dispatch behavior.

The rules use normal raw-table priority, leaving fragment reassembly and the
1,500-byte capture limit unchanged. They do not change interface MTU or provide
PMTU discovery; necessary ICMP errors still need to reach the responsible stack.
`skip-sysctl` does not disable NOTRACK setup.

All INPUT queue rules are installed before any enabled NOTRACK rules. The
coordinator services the inactive queues with `NF_ACCEPT` during these supervised
rule commands. Capture activates once its selected rules are installed.
If multiqueue rule installation fails, WaterWall removes the partial rules and
retries one receive queue. Failed single-queue installation, NOTRACK installation,
or incomplete rollback fails startup.
Cleanup attempts NOTRACK removal before NFQUEUE removal and tracks failed or
outcome-unknown commands independently in their respective tables. A NOTRACK
cleanup failure does not prevent an attempt to remove the queue rules. Reader
failure requests orderly shutdown, whose lifecycle owner performs rule cleanup.
Removing NOTRACK restores tracking for subsequent packets; already-untracked
packets are not retroactively tracked. `--queue-bypass` affects only NFQUEUE:
abrupt process death or failed cleanup can leave `WWCAP_NOTRACK_...` rules that
an administrator must remove from `raw PREROUTING` to restore tracking.

On Linux, the NFQUEUE rules use `--queue-bypass`. If WaterWall is not listening
on the queue, matching packets continue through the host firewall instead of
being dropped by an absent queue. This is a fail-open availability policy:
packets are not captured or transformed while no listener exists. It does not
make queue overflow fail-open while WaterWall remains bound to the queue.
WaterWall avoids queue numbers already referenced by existing INPUT rules. A
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

### Checksum behavior

Before writing a packet, `RawSocket` checks the packet buffer request:

- if `sbufGetRecalculateChecksum(buf)` is true, checksums are recomputed
- full packet checksum recalculation is attempted
- for fragmented IPv4 packets, transport checksum recalculation is skipped automatically and only the IPv4 header checksum is recomputed

### Why `TunDevice` may be a better fit for some cases

The current `RawSocket` implementation is focused on capturing inbound IPv4 traffic that matches a source-IP filter and injecting raw IPv4 packets.

If you need a virtual interface model or packet handling that is closer to routed interface traffic, `TunDevice` is usually the better match.

### Callback and line lifecycle

Payload is the meaningful callback path. Ordinary connection lifecycle
callbacks (`Init`, `Est`, `Pause`, and `Resume`) are terminal absorbers at this
packet adapter. An unexpected `Finish` in either direction is a fatal packet-line
lifecycle violation and aborts the program; it is not a no-op.

The chain owns one persistent packet line per worker. `RawSocket` never destroys
those lines and has zero bytes of line state.

## Notes And Caveats

- The current receive path only forwards IPv4 packets.
- `capture-filter-mode` is effectively limited to `"source-ip"` when capture is enabled.
- Omitting capture ranges intentionally selects write-only raw packet injection.
- Platform support depends on the raw/capture backend available on the operating system.

## Node Metadata

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

### `fragment-policy` (optional, default: `reassemble`)

Omitting this setting selects `reassemble`: IPv4 fragments are assembled before
publication into the chain. `preserve-fragments` keeps their bytes and boundaries.
The policy does not impose a node-name or topology allowlist; ordinary layer and
chain validation still applies. Invalid values (including `null`) fail startup.

`PacketsToConnection` upstream packet input and `ConnectionToPackets` downstream
packet input require complete IPv4 datagrams. Any fragment reaching either input
is a runtime contract violation: a fatal diagnostic explains the reassembly
requirement and the process exits, in Debug and Release. Reassemble before these
consumers, regardless of the device policy or intervening nodes. DF alone is not
a fragment; MF or a nonzero fragment offset is.

Reassembly emits complete IPv4 datagrams up to 65,535 bytes. It does not raise
packet-output limits or device MTU, and does not automatically fragment output
again. See Developer Guide Part 4 for assembly bounds and packet ownership.
