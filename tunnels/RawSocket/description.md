<!--
Documentation version: 159
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/RawSocket.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/RawSocket.mdx, and all files must keep the same documentation version.
-->

# RawSocket Node

`RawSocket` connects WaterWall to raw IPv4 packet capture and raw packet injection. When capture ranges are configured, it captures matching IP packets from the host networking stack and forwards them into the chain. Independently, it can inject raw IP packets coming from the chain back into the system.

This node is a layer-3 adapter rather than a connection-oriented tunnel.

## What It Does

- Optionally creates a capture device for matching IPv4 packets.
- Creates a raw output device for sending raw IPv4 packets.
- When capture is enabled, captures packets that match the configured IP, protocol and optional TCP port filters and drops them from the host kernel network stack so only WaterWall receives and accesses them.
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

  Excluded incoming packets skip this node's capture and incoming NOTRACK rules,
  including when `bypass-conntrack` is enabled. They continue through normal host
  conntrack and firewall processing. This setting does not restrict raw output:
  packets sent by WaterWall's raw socket still follow `bypass-conntrack`.

  For example, these settings leave incoming ICMP and TCP to the host:

  ```json
  { "dont-capture-protocols": [1, 6] }
  ```

- `capture-protocols` `(array of integers)`
  Capture only the literal IPv4 Protocol bytes listed here, for example `[6]`
  for TCP-shaped packets on both fake-TCP peers. Entries must be whole numbers
  from `0` through `255`; duplicates are ignored. Omission preserves the default
  of all protocols. An explicit empty array captures none. This setting and
  `dont-capture-protocols` are mutually exclusive, even for empty lists.

  The allowlist is compiled once into the existing protocol predicate: Linux
  uses fixed-size cBPF in both NFQUEUE and incoming NOTRACK rules; Windows uses
  WinDivert. Unselected protocols stay in the host stack and retain normal
  conntrack/firewall processing. Raw output is unaffected. Nonempty exclusions,
  including those produced from this allowlist, require Linux's iptables `bpf`
  match. Source-IP capture ranges still apply. Protocol `[6]` alone also
  captures ordinary TCP from matching peers; narrow a fake-TCP carrier to its
  reserved port pair with the settings below.

- `capture-tcp-source-port` / `capture-tcp-dest-port` `(integer)`
  Optional exact TCP source and destination port qualifiers, each in
  `1..65535`. Omission leaves that port unrestricted; zero, null, fractions,
  wrong types and out-of-range values are rejected. Either qualifier implies
  TCP-only capture and is combined with the existing source-IP and protocol
  predicates. If both ports are present, both must match. Configurations that
  exclude TCP through `capture-protocols` or `dont-capture-protocols` are rejected
  when a port qualifier is set.

  Port-qualified capture excludes all IPv4 fragments, including fragment zero,
  before NFQUEUE and incoming NOTRACK. Other ports and non-TCP traffic continue
  through the host stack and normal conntrack/firewall processing. Raw output
  is unaffected. Linux compiles a fixed-size cBPF predicate at startup and uses
  it in both rules; this requires the iptables `bpf` match. Windows uses
  WinDivert's TCP port and fragment predicates.

  For a fake-TCP client whose local carrier port is `40001` and peer port is
  `40000`, capture replies with:

  ```json
  {
    "capture-filter-mode": "source-ip",
    "capture-ips": ["198.51.100.10"],
    "capture-protocols": [6],
    "capture-tcp-source-port": 40000,
    "capture-tcp-dest-port": 40001
  }
  ```

  At the server, use the client's source IP and reverse the port values.
  Reserve this carrier port pair so ordinary applications do not use the same
  peer tuple. Port matching separates unrelated TCP traffic but does not
  authenticate packets. See [FakeTcpHeader](../FakeTcpHeader/description.md)
  for the packet-envelope and MTU configuration.

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

Without TCP port qualifiers, all IPv4 fragments, including fragment zero, retain
address/protocol kernel steering. The shared fragment table keeps its existing staging and fragment-zero
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

The capture device is configured from the ranges supplied through either `capture-ips` or `capture-ip`. Captured packets matching the configured source IP, protocol and optional TCP port filters are dropped from the host kernel networking stack: normal local transport delivery stops while capture is active, and WaterWall processes its captured copy.

Current implementation behavior:

- on Windows, the capture filter combines `ip.SrcAddr` equality or inclusive range checks with exclusions on `ip.Protocol` and any configured TCP port qualifiers
- on Linux, multiqueue capture creates a flow rule per queue and range; only `spread` adds random opaque rules. Single-queue capture creates one queue rule per range
- `capture-filter-mode` is parsed, but only the `source-ip` path is currently implemented

On Linux, protocol exclusions or TCP port qualifiers require the iptables `bpf`
match (`xt_bpf`). One fixed-size classic BPF predicate is used in both the
NFQUEUE and incoming NOTRACK rules. Without port qualifiers it checks the
literal IPv4 Protocol byte, including fragments and protocol zero, without
interpreting transport headers. With port qualifiers it admits only whole TCP
packets with the selected ports, using the actual IPv4 header length. Missing
matcher support fails startup and rolls back installed rules. An unrestricted
protocol selection with no port qualifiers adds no matcher. Windows applies
the same protocol and port selection in its WinDivert filter.

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

### `opaque-flow-mode` (optional, default: `prefix`)

Accepts only the exact strings `prefix`, `peer`, `spread` and `auto`. Empty or
unknown strings, `null` and other JSON types fail construction on every platform,
including write-only RawSocket. Omission always selects `prefix`, even beside Ping.
The setting is independent of `multi-queue`, `gso` and `fragment-policy`; a single
receive queue still dispatches over the configured processing workers.

For structurally valid, unfragmented IPv4 with Protocol other than TCP (6) or
UDP (17):

| Value | Receive worker selection |
| --- | --- |
| `prefix` | Symmetric hash of addresses, protocol and the first four IP-payload bytes as two big-endian 16-bit endpoint fields. |
| `peer` | Hash addresses and protocol only; ignore every payload byte. |
| `spread` | Spread packets using the backend's existing mechanism. |
| `auto` | Resolve once at startup using the exact direct Ping decoding neighbour below; otherwise use `prefix`. |

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
only for the immediate physical node of exact type `PingServer`; downstream
publication toward `prev` selects `peer` only for exact type `PingClient`.
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
Ping passes unrelated packets through, so automatic `peer` groups unrelated
opaque traffic as well; mixed traffic may require an explicit setting. Startup
logs requested mode, effective mode, selection reason and effective queue count.

### `fragment-policy` (optional, default: `reassemble`)

Omitting this setting selects `reassemble`: IPv4 fragments are assembled before
publication into the chain. `preserve-fragments` keeps their bytes and boundaries.
The policy does not impose a node-name or topology allowlist; ordinary layer and
chain validation still applies. Invalid values (including `null`) fail startup.

TCP port qualifiers reject fragments before capture, so neither fragment policy
can publish fragmented carrier packets when a TCP port qualifier is enabled.

`PacketsToConnection` upstream packet input and `ConnectionToPackets` downstream
packet input require complete IPv4 datagrams. Any fragment reaching either input
is a runtime contract violation: a fatal diagnostic explains the reassembly
requirement and the process exits, in Debug and Release. Reassemble before these
consumers, regardless of the device policy or intervening nodes. DF alone is not
a fragment; MF or a nonzero fragment offset is.

Reassembly emits complete IPv4 datagrams up to 65,535 bytes. It does not raise
packet-output limits or device MTU, and does not automatically fragment output
again. See Developer Guide Part 4 for assembly bounds and packet ownership.
