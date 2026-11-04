<!--
Documentation version: 156
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TcpOverUdpServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/TcpOverUdpServer.mdx, and all files must keep the same documentation version.
-->

# TcpOverUdpServer Node

`TcpOverUdpServer` is the server-side peer of `TcpOverUdpClient`. It receives UDP-style packet traffic carrying KCP data, reconstructs the original byte stream, and forwards that stream to the next node.

In practice, this node is used together with `TcpOverUdpClient` on the other side of the packet path.

## What It Does

- Accepts packet payload from the previous node.
- Feeds those packets into KCP.
- Reconstructs a TCP-like stream from the KCP session.
- Forwards the reconstructed stream to the next node.
- Accepts downstream stream replies, re-encodes them into KCP, and sends them back as packets.
- Uses internal ping and close frames to maintain the session.

This node expects the previous side of the chain to provide packet-preserving transport.

## Typical Placement

A common layout is:

- a UDP-capable tunnel or transport before `TcpOverUdpServer`
- `TcpOverUdpServer`
- one or more stream-facing service nodes after it

It should usually sit opposite `TcpOverUdpClient`.

## Configuration Example

```json
{
  "name": "tcp-over-udp-server",
  "type": "TcpOverUdpServer",
  "settings": {
    "fec": true,
    "fec-data-shards": 10,
    "fec-parity-shards": 3,
    "kcp-send-window": 8192,
    "kcp-recv-window": 8192,
    "no-recv-timeout-ms": 30000,
    "close-drain-timeout-ms": 30000
  },
  "next": "service-stream-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TcpOverUdpServer"`.

- `next` `(string)`
  The next node that should receive the reconstructed stream.

### `settings`

There are no required tunnel-specific settings.

## Optional `settings` Fields

- `send-mtu` `(integer)`
  IPv4-based outgoing packet budget in bytes: `118..65535` without FEC, or `126..65535` with FEC. Receiving uses independent protocol limits.
  Default: core `misc.mtu` (normally `1500`)

- `fec` `(boolean)`
  Enables Reed-Solomon forward error correction around the KCP datagrams.
  If omitted or `false`, KCP datagrams use the session envelope without FEC.

- `fec-data-shards` `(number)`
  Number of source shards per FEC block when `fec` is enabled.
  Default: `10`

- `fec-parity-shards` `(number)`
  Number of parity shards per FEC block when `fec` is enabled.
  Default: `3`

- `kcp-nodelay` `(boolean)`
  Enables KCP nodelay mode.
  Default: `true`

- `kcp-interval-ms` `(number)`
  KCP update interval in milliseconds.
  Default: `10`

- `kcp-resend` `(number)`
  KCP fast-resend threshold.
  Default: `2`

- `kcp-no-congestion-control` `(boolean)`
  Disables KCP congestion control for higher-throughput UDP paths.
  Default: `true`

- `kcp-send-window` `(number)`
  KCP send window in segments.
  Default: `8192`

- `kcp-recv-window` `(number)`
  KCP receive window in segments.
  Default: `8192`

- `kcp-initial-cwnd` `(number)`
  Initial KCP congestion window in segments. If omitted, it defaults to half of `kcp-send-window`.
  Default with the built-in send window: `4096`

- `kcp-rx-minrto-ms` `(number)`
  Minimum KCP retransmission timeout in milliseconds.
  Default: `30`

- `kcp-send-buffer-limit` `(number)`
  Backpressure threshold for queued KCP packets. `0` derives the limit from local send window + remote window + `10`, capped at `2147483647`.
  Default: `0`

- `ping-interval-ms` `(number)`
  Time without received packets before sending an internal ping.
  Default: `10000`

- `no-recv-timeout-ms` `(number)`
  Time without received packets before closing the line. Must be greater than `ping-interval-ms`.
  Default: `30000`

- `close-drain-timeout-ms` `(integer)`
  Maximum send/drain interval and ACK-retention interval, negotiated as the minimum of both peers. Range: `1..2147483647`. Increasing the effective interval requires both peers to allow it.
  Default: `30000`

## Detailed Behavior

### KCP transport model

Incoming Init initializes the borrowed UDP carrier only. A HELLO, CHALLENGE,
CONFIRM, READY exchange with independent 128-bit nonces establishes each session.
The service branch receives Init exactly once after a matching CONFIRM. Each
session owns a distinct service line while its KCP/FEC state survives separately
from that line.

Every datagram has a 40-byte explicitly serialized session envelope: magic
`WWKC`, kind, zero reserved byte, two-byte network-order body length, 16-byte
client nonce and 16-byte server nonce. Kinds are HELLO `1`, CHALLENGE `2`, CONFIRM
`3`, READY `4`, KCP `5`, and FEC `6`. Handshake bodies contain the four-byte
network-order close interval, data/parity shard counts and two zero reserved
bytes. Both nonces are validated before KCP or FEC input; unknown sessions cannot
open a service. These nonces identify sessions; they add no encryption or authentication.

The client retries its current handshake request every 250 ms until its original
`no-recv-timeout-ms` deadline. A carrier admits one pending challenge with a fixed
expiry and at most 64 established sessions, including draining and ACK-retention
sessions. At capacity, new admission is refused without truncating existing retention;
client retries remain bounded by their original deadline. Reusing a UDP endpoint creates fresh
session/service identities while old sessions can continue acknowledging retries.
This per-carrier cap is not a process-wide KCP/FEC heap budget.

Incoming KCP records carry a one-byte internal frame flag. Replies are chunked,
framed and sent through KCP toward the previous side. Actual transport Est maps
promptly between associated lines; protocol readiness remains separate. KCP/FEC
callbacks stage output before neighboring tunnels run, and nested input is
serialized with finite byte/allocation-charge admission.

### Internal frame flags

Inside the KCP payload, this tunnel uses:

- `0x00`: data
- `0xF0`: ping
- `0xFF`: close

Data frames carry stream bytes after the flag byte.

Data frames containing only the flag are discarded. An empty KCP message has no
flag and closes the affected connection, as does an unknown flag or a completed
KCP message larger than the local receive buffer. Incomplete KCP messages wait
for their remaining fragments.

### Default KCP settings

The implementation exposes KCP tuning in JSON. The higher-throughput defaults are:

- `kcp-nodelay = true`
- `kcp-interval-ms = 10`
- `kcp-resend = 2`
- `kcp-no-congestion-control = true`
- `kcp-send-window = 8192`
- `kcp-recv-window = 8192`
- `kcp-initial-cwnd = 4096`
- `kcp-rx-minrto-ms = 30`
- `kcp-send-buffer-limit = 0` (derived from KCP windows)
- `ping-interval-ms = 10000`
- `no-recv-timeout-ms = 30000`

### Sending MTU

Optional integer `send-mtu` inherits core `misc.mtu` at construction (the core fallback
is 1500). The supported range is **118..65535 without FEC**, or **126..65535 with
FEC**. It is an IPv4-based outgoing packet budget in bytes. Invalid explicit or inherited
values reject construction; an explicit supported override can replace an
unsupported core default. Null, wrong types, fractions, zero, negatives and
out-of-range numbers are errors. Each instance keeps its validated sending MTU unchanged.

With `F = 0` without FEC or `F = 8` with FEC:

```text
KCP MTU = min(send-mtu - 20 - 8 - 40 - F, 64000)
application chunk = KCP MTU - 24 - 1
```

The 20-byte IPv4, 8-byte UDP and 40-byte session-envelope allowances are fixed. The 64,000-byte decimal cap
covers the complete KCP packet, including its 24-byte header. The one-byte frame
flag occupies KCP payload space; `required_padding_left = 1` provides room for it.
The effective KCP MTU governs data and aggregated acknowledgement/control output.
FEC adds at most 8 bytes to that output, including parity packets.

Receiving uses independent protocol limits: at most 64000 bytes for a KCP packet,
or 64008 bytes for an FEC shard, excluding the 40-byte session envelope. Peers
may use different `send-mtu` values. An incoming packet is not rejected merely
because it exceeds the receiver's own sending budget; framing, session identity,
and FEC validation still apply. There is no MTU negotiation.

At `send-mtu: 1500`, KCP MTU/application chunk are **1432/1407** without FEC and
**1424/1399** with FEC. Budgets of 64068 without FEC or 64076 with FEC reach the
cap; larger valid settings, including 65535, retain KCP MTU 64000 and application
chunk 63975. The configured budget itself is not capped to 64000.

This is not path-MTU discovery or negotiation. An ordinary IPv6 header needs 20
more bytes than the fixed IPv4 allowance, so a 1500 budget can permit a 1520-byte
IPv6 packet. IPv4 options, IPv6 extension headers and later wrappers need extra
operator headroom. No family-dependent adjustment occurs.

### Optional FEC layer

When `fec` is enabled, the server expects the previous side to carry FEC-wrapped KCP packets that match the configured shard counts.

On receive, it:

- feeds direct data shards into KCP immediately
- tries to reconstruct missing KCP datagrams from parity shards
- ignores invalid FEC packets conservatively

On send, it wraps outbound KCP datagrams in the same FEC format and emits parity shards after each configured data block.

When `fec` is disabled, each session envelope carries one KCP packet directly.

### Data flow direction

- Packet side to stream side: previous node -> `TcpOverUdpServer` -> next node
- Stream replies back to packet side: next node -> `TcpOverUdpServer` -> previous node

Incoming KCP data frames are decoded and forwarded to the next node as stream payload.

Outgoing stream payload is split into KCP-friendly chunks, tagged as data frames, and sent back through the previous side.

### Close and timeout behavior

Service Finish detaches and destroys the owned service line immediately while
its independent session keeps accepted output. From that first closing event,
the session has one fixed negotiated interval D to acknowledge earlier data,
then enqueue CLOSE once and wait for KCP acknowledgment of CLOSE itself. A flush
alone never confirms close. Timeout settles sending as unconfirmed.

Peer CLOSE retires the service after preceding inbound bytes, once, and fixes
any local queued-output drain budget before publishing its KCP ACK. The receive
state remains available for duplicate CLOSE acknowledgments after application
EOF. A peer-only responder remains for D after first CLOSE receipt. When our
CLOSE is acknowledged at A, receive state remains until A + D; a later peer CLOSE
does not extend it. An expired local sender preserves any earlier peer-ACK
obligation while suppressing further application/CLOSE PUSH output.

With the default, sending gets at most 30 seconds and ACK-capable state can
remain for up to 60 seconds from the first closing event. This bounds transport
receipt, not remote application consumption or persistence. No TCP half-close
semantics are added. Transport Finish, fatal protocol failure and shutdown abort
immediately; shutdown never waits for graceful-close deadlines.

Normal sessions ping after `ping-interval-ms` of silence and expire after
`no-recv-timeout-ms`. Closing sessions use their fixed close deadlines instead
of letting the normal idle check truncate promised ACK retention. Invalid or
unrelated packets refresh no session deadline. Once no session or pending
challenge needs a carrier, local state is cleared and the UDP owner receives
Finish. Closing one session preserves a carrier still needed by another.

### Backpressure behavior

Pause and Resume are repeatable advisory notifications. Received signals pass
through, except toward the already-finished stream side during close-frame
flushing. KCP data, acknowledgements, retransmissions and due pings do not wait
for Resume; KCP windows and timers still control protocol progress.

After an admitted stream payload is encoded and KCP output settles, a send queue
above `kcp-send-buffer-limit` triggers one Pause toward the next side. When the
queue falls below that threshold, the node releases its own pressure with Resume,
including when an incoming ACK drains it without producing another packet. When
the setting is `0`, the threshold comes from the current KCP windows. This is an
advisory threshold in KCP segments, not a hard admission limit.

The node remains active for the entire line: every payload needs KCP and optional
FEC processing, and the session retains its timers and close protocol. It cannot
bypass itself after setup.

## Notes And Caveats

- `TcpOverUdpServer` is intended to be paired with `TcpOverUdpClient`.
- FEC must be enabled on both peers with matching shard settings.
- The previous node should preserve packet boundaries.
- `DownStreamInit` is disabled; service lines are created through the upstream handshake.
- Worker shutdown cancels timers and drains every owned service/session immediately.

## Node Metadata

Source-backed metadata:

This node explicitly disables splice for the entire chain through
`kNodeFlagBlocksSplice`, even if `kNodeFlagSupportsSplice` is also set.

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagBlocksSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `1` byte |
