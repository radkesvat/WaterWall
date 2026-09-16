<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/RawSocket.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/RawSocket.mdx, and all files must keep the same documentation version.
-->

# RawSocket Node

`RawSocket` connects WaterWall to raw IPv4 packet capture and raw packet injection. When capture ranges are configured, it captures matching IP packets from the host networking stack and forwards them into the chain. Independently, it can inject raw IP packets coming from the chain back into the system.

This node is a layer-3 adapter rather than a connection-oriented tunnel.

## What It Does

- Optionally creates a capture device for matching IPv4 packets.
- Creates a raw output device for sending raw IPv4 packets.
- When capture is enabled, captures packets that match the configured IP filter and drops them from the host kernel network stack so only WaterWall receives and accesses them.
- Forwards captured packets to the adjacent chain side.
- Writes raw IP packets from the chain out through the raw device.
- Applies checksum recalculation before writing when the line requests it.
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
PingServer. PingServer sends an exact type-0 Echo Reply back toward RawSocket
before restoring the inner packet toward TunDevice. Plain packets from TunDevice
return downstream as fresh type-8 Echo Requests for raw injection; they are not
inserted into an unrelated Echo Reply.

## Configuration Example

```json
{
  "name": "raw-ip",
  "type": "RawSocket",
  "settings": {
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

- `capture-filter-mode` `(string)`
  Filter mode for captured traffic. This field is required when at least one capture range is configured and is ignored in write-only mode.

  Parsed values are:
  - `"source-ip"`
  - `"dest-ip"`

  The current implementation only accepts `"source-ip"`. If `"dest-ip"` is selected, tunnel creation fails with a message telling you to use `TunDevice` for outgoing capture instead.

- `skip-sysctl` `(boolean)`
  On Linux, skip Capture's best-effort `sysctl` performance tuning. NFQUEUE socket configuration and the iptables rules required to direct packets into NFQUEUE still run.

  Default: `false`

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
  "settings": { "bypass-conntrack": false, "mark": 10 }
  ```

## Detailed Behavior

### Capture path

During `onStart`, `RawSocket`:

- when at least one capture range is configured, decides which adjacent tunnel should receive captured packets and creates the capture device
- creates the raw output device
- brings the raw output device up before activating capture rules

With no configured capture range, no capture device, NFQUEUE socket, capture reader, or capture rule is created. Only the raw output device is started.

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

Fragment affinity follows the captured packet buffer through forwarding, delay, one-to-one copies, duplication, worker
handoff, and cleanup rather than ending at queue admission or callback return. Copies share one counted settlement
claim, and the reader session remains alive until the last copy is consumed. If an identity expires or its reader
generation ends with a claim outstanding, late copies are refused before lwIP and the key remains poisoned until its
factual or conservative final settlement. If publication is only partially admitted, producer admission closes
immediately, the capture reader exits (allowing Linux NFQUEUE's `--queue-bypass` lifecycle to take over), and orderly
shutdown is requested. This prevents later same-ID packets from completing a hybrid datagram with fragments already
queued to lwIP.

### Output path

When payload reaches `RawSocket` from upstream or downstream:

- the payload is treated as a raw IP packet
- the complete packet is structurally validated as exact IPv4, even when no
  checksum recalculation was requested; trailing bytes and malformed or
  truncated packets are dropped
- checksum recalculation is performed if requested by the line
- the packet is written through the raw device

Both upstream and downstream payload handlers write to the same raw output device.

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

The writer stops and joins before its `WWRAW_NOTRACK_...` rule is removed.
Startup rollback and destruction retry pending cleanup, including commands with
uncertain outcomes. Abrupt process death or persistent command failures can
leave this exact-mark rule in `raw OUTPUT`; remove the rule identified by its
logged comment if cleanup cannot complete.

### Capture filter behavior

The capture device is configured from the ranges supplied through either `capture-ips` or `capture-ip`. Captured packets matching the configured source IP filter are dropped from the host kernel networking stack: normal local transport delivery stops while capture is active, and WaterWall processes its captured copy.

Current implementation behavior:

- on Windows, the capture filter is built from equivalent `ip.SrcAddr` equality or inclusive range checks
- on Linux, one netfilter queue rule is created for each configured IPv4 address or CIDR range
- `capture-filter-mode` is parsed, but only the `source-ip` path is currently implemented

By default the Linux capture backend also applies best-effort `sysctl` tuning before creating NFQUEUE resources. `"skip-sysctl": true` suppresses only that tuning batch. The netlink operations and iptables commands needed to configure NFQUEUE remain enabled.

When `bypass-conntrack` is enabled (the default), Linux capture installs a
matching `CT --notrack` rule in `raw PREROUTING` for each capture source range.
The exemption also requires `--dst-type LOCAL`: it covers packets addressed to a local unicast address,
without exempting ordinary transit traffic, broadcasts, or multicast. The INPUT
capture rule still uses its existing source-only match. Raw-table matching is
before DNAT, so exempted traffic cannot rely on this host's conntrack-based NAT
or stateful firewall handling. Setting `bypass-conntrack=false` disables these
capture exemptions along with the output exemption. NFQUEUE capture continues
with its existing drop-and-dispatch behavior.

The rules use normal raw-table priority, leaving fragment reassembly and the
1,500-byte capture limit unchanged. They do not change interface MTU or provide
PMTU discovery; necessary ICMP errors still need to reach the responsible stack.
`skip-sysctl` does not disable NOTRACK setup.

All INPUT queue rules are installed before any enabled NOTRACK rules, with the
reader already ready. Capture activates once its selected rules are installed.
Startup fails and rolls back installed rules if either installation fails.
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
terminal capture startup or rule-cleanup failure closes the queue promptly and
makes that capture-device object non-restartable, activating `--queue-bypass`
for any NFQUEUE rule that could not be removed. The queue reader must report ready
before the first rule is installed and remains running throughout rule
insertion, rollback, and bring-down cleanup. Until every rule is installed and
the raw output device is ready, packets receive `NF_ACCEPT` and are not
dispatched into the chain. Capture then switches to drop-and-dispatch. Shutdown
deactivates capture before removing rules. An unexpected reader exit
deactivates capture and closes the queue immediately so remaining rules fail
open. While a reader thread is joinable, it owns the queue descriptor;
terminal cleanup requests closure, and the reader wrapper closes the queue only
after the routine has stopped using that descriptor.

### Checksum behavior

Before writing a packet, `RawSocket` checks line flags:

- if `recalculate_checksum` is set, checksums are recomputed
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
