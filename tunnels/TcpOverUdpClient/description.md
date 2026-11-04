<!--
Documentation version: 156
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TcpOverUdpClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/TcpOverUdpClient.mdx, and all files must keep the same documentation version.
-->

# TcpOverUdpClient Node

`TcpOverUdpClient` carries a TCP-like byte stream over a UDP path by running KCP internally. It accepts stream data from the previous node, feeds it into KCP, and sends the resulting packets through the next node.

In practice, this node is used together with `TcpOverUdpServer` on the remote side.

## What It Does

- Accepts stream payload from the previous node.
- Encodes that stream into KCP segments.
- Adds a 1-byte internal frame flag to KCP payloads.
- Sends the resulting datagrams through the next node.
- Receives datagrams back from the next node, feeds them into KCP, and reconstructs the stream.
- Uses periodic ping frames and an idle timeout to detect dead peers.

This node expects the next side of the chain to preserve packet boundaries. In practice that means a UDP-capable transport path.

## Typical Placement

A common layout is:

- a stream-producing node before `TcpOverUdpClient`
- `TcpOverUdpClient`
- a UDP-capable tunnel or transport after it
- `TcpOverUdpServer` on the remote side
- service-facing stream nodes after `TcpOverUdpServer`

This pair is useful when you want stream semantics on top of a datagram path.

## Configuration Example

```json
{
  "name": "tcp-over-udp-client",
  "type": "TcpOverUdpClient",
  "settings": {
    "fec": true,
    "fec-data-shards": 10,
    "fec-parity-shards": 3,
    "kcp-send-window": 8192,
    "kcp-recv-window": 8192,
    "no-recv-timeout-ms": 30000
  },
  "next": "udp-path-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TcpOverUdpClient"`.

- `next` `(string)`
  The next node that should carry the UDP-style packet traffic.

### `settings`

There are no required tunnel-specific settings.

## Optional `settings` Fields

- `send-mtu` `(integer)`
  IPv4-based outgoing packet budget in bytes: `118..65535` without FEC, or `126..65535` with FEC. Receiving uses independent protocol limits.
  Default: core `misc.mtu` (normally `1500`)

- `fec` `(boolean)`
  Enables Reed-Solomon forward error correction around the KCP datagrams.
  If omitted or `false`, session-identified KCP datagrams are sent without FEC.

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

- `close-drain-timeout-ms` `(integer)`
  Finite close send/retention interval. Default: `30000`; range: `1..2147483647`.
  Both peers negotiate the smaller setting; increasing it requires both endpoints to allow it.

- `no-recv-timeout-ms` `(number)`
  Time without received packets before closing the line. Must be greater than `ping-interval-ms`.
  Default: `30000`

## Detailed Behavior

### KCP transport model

During application Init, the client borrows that application line and creates a separate owned UDP transport line on the same worker. It copies routing contexts, listener/source ports, credentials and read policy before transport Init. Application context is TCP; transport context is UDP. Actual transport Est is relayed promptly to the attached application, independently of handshake readiness.

The peers establish a fresh session through HELLO, CHALLENGE, CONFIRM and READY. Independent 128-bit client/server nonces identify every KCP/FEC datagram before decoding. Handshake messages carry the close interval and exact FEC settings. The client retries its current request every 250 ms within the original `no-recv-timeout-ms` deadline. The server initializes a distinct service line only after fresh confirmation. Delayed traffic cannot reset an established session or recreate an old service. These identifiers provide no authentication or encryption.

Accepted application data enters KCP's ordered send queue before readiness; ordinary wire output waits for matching READY. Nested callbacks are serialized with bounded retained-buffer storage.

Stream payload arriving from the previous node is split into chunks small enough to fit into the configured KCP write MTU and then sent through KCP.

The remote `TcpOverUdpServer` performs the reverse operation and exposes the reconstructed stream again.

### Internal frame flags

Inside the KCP payload, this tunnel uses a 1-byte flag:

- `0x00`: data
- `0xF0`: ping
- `0xFF`: close

Data frames carry real stream bytes after the first byte.

Ping frames are only used as keepalive markers. Close frames request shutdown of the paired line.

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

The 20-byte IPv4 and 8-byte UDP allowances are fixed. Every packet also carries a 40-byte session envelope outside KCP/FEC. The 64,000-byte decimal cap
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

When `fec` is enabled, the tunnel wraps each outbound KCP datagram in a Reed-Solomon FEC packet and emits parity packets after each configured data-shard block.

On receive, it:

- accepts FEC-wrapped KCP datagrams
- feeds normal data packets into KCP immediately
- tries to recover missing KCP datagrams from parity packets
- drops invalid FEC packets conservatively

When `fec` is disabled, the session envelope directly contains one KCP datagram.

### Data flow direction

- Stream to UDP/KCP side: previous node -> `TcpOverUdpClient` -> next node
- UDP/KCP side back to stream: next node -> `TcpOverUdpClient` -> previous node

On the send side, `TcpOverUdpClient` breaks the stream into KCP-friendly chunks and forwards the resulting packet traffic to the next node.

On the receive side, it feeds incoming packet payloads into KCP, drains completed KCP data, strips the 1-byte flag, and forwards reconstructed stream payload downstream to the previous node.

### Close and timeout behavior

Application Finish immediately detaches and clears the borrowed application state. Its owner may destroy that line as soon as Finish returns. The owned transport and stable session continue draining previously accepted KCP output for the negotiated interval `D = min(client setting, server setting)`.

The fixed send deadline starts at the first local Finish or peer CLOSE. Once preceding data is acknowledged, the sender queues CLOSE exactly once and waits for its KCP acknowledgment. A flush alone never confirms delivery. At the deadline, unacknowledged sending stops and is reported unconfirmed. Received traffic and handshake progress never extend that deadline. Finish before negotiation uses the local interval initially and can only shorten it after negotiation.

On peer CLOSE, preceding inbound data is delivered before application Finish, the application retires once, and accepted outgoing data retains the same bounded drain. The driver enters closing before publishing the KCP CLOSE ACK. It keeps KCP receive state so duplicate CLOSE packets receive another ACK without reopening an application or extending retention.

A peer-only responder remains until first CLOSE receipt plus D. A locally acknowledged CLOSE at A retains an ACK-capable responder until A + D, including simultaneous close. Expired local sending preserves an earlier peer-ACK obligation. Retention is at most 2D from the first closing event: with defaults, at most 30 seconds to send and 60 seconds total. ACK-only retention uses a deadline timer and input-triggered ACK flushes, with expired PUSH output filtered before FEC.

`no-recv-timeout-ms` independently detects silence during ordinary operation; fixed close deadlines govern closing. Transport Finish, fatal protocol failure and process shutdown abort immediately. Worker quiescence detaches timer roots, and worker Stop drains all owned transports without waiting for graceful close. KCP acknowledgment confirms peer transport receipt, not remote application consumption or persistence. This protocol does not provide TCP half-close.

### Backpressure behavior

Pause and Resume are repeatable advisory signals and are forwarded transparently. Ready data, retransmissions, acknowledgements and due pings do not wait for Resume.

After admitting the complete input and settling KCP packet output, the node compares its send queue with `kcp-send-buffer-limit`. Crossing above that threshold requests Pause toward the previous side; falling below it releases that local hold with Resume. When the setting is `0`, the threshold is derived from the current KCP windows. ACK-only input can release the hold without another outgoing packet. Notifications are sent synchronously after KCP processing, preserving input order and safe reentrant Finish handling.

This setting is a soft segment-count threshold, not a hard memory or admission limit. KCP windows and the receive timeout remain in force. The node cannot bypass itself: every payload still needs KCP/FEC processing, and its reliability and timeout state remain necessary.

## Notes And Caveats

- `TcpOverUdpClient` is intended to be paired with `TcpOverUdpServer`.
- FEC must be enabled on both peers with matching shard settings.
- The next node should preserve datagram boundaries.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.

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
