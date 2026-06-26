<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TcpOverUdpServer.mdx, and both files must keep the same documentation version.
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
    "no-recv-timeout-ms": 30000
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

- `fec` `(boolean)`
  Enables Reed-Solomon forward error correction around the KCP datagrams.
  If omitted or `false`, the tunnel keeps the old KCP-only behavior.

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
  Backpressure threshold for queued KCP packets. `0` keeps the derived limit: local send window + remote window + `10`.
  Default: `0`

- `ping-interval-ms` `(number)`
  Time without received packets before sending an internal ping.
  Default: `10000`

- `no-recv-timeout-ms` `(number)`
  Time without received packets before closing the line. Must be greater than `ping-interval-ms`.
  Default: `30000`

## Detailed Behavior

### KCP transport model

When a line is initialized, `TcpOverUdpServer` creates a KCP session, starts the KCP timer loop, and queues an initial ping frame.

Incoming packet payloads from the previous node are fed into KCP. Completed KCP payloads are then read out and interpreted using a 1-byte internal frame flag.

Replies from the next node are chunked, wrapped, and sent back through KCP toward the previous side.

### Internal frame flags

Inside the KCP payload, this tunnel uses:

- `0x00`: data
- `0xF0`: ping
- `0xFF`: close

Data frames carry stream bytes after the flag byte.

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

KCP MTU is also taken from `GLOBAL_MTU_SIZE`.
If FEC is enabled, the tunnel subtracts the FEC wire overhead from the outer KCP/UDP packet budget so the transport stays inside the same MTU envelope.

### Optional FEC layer

When `fec` is enabled, the server expects the previous side to carry FEC-wrapped KCP packets that match the configured shard counts.

On receive, it:

- feeds direct data shards into KCP immediately
- tries to reconstruct missing KCP datagrams from parity shards
- ignores invalid FEC packets conservatively

On send, it wraps outbound KCP datagrams in the same FEC format and emits parity shards after each configured data block.

When `fec` is disabled, the behavior remains the original KCP-only transport path.

### Data flow direction

- Packet side to stream side: previous node -> `TcpOverUdpServer` -> next node
- Stream replies back to packet side: next node -> `TcpOverUdpServer` -> previous node

Incoming KCP data frames are decoded and forwarded to the next node as stream payload.

Outgoing stream payload is split into KCP-friendly chunks, tagged as data frames, and sent back through the previous side.

### Close and timeout behavior

If a close frame is received from the remote peer, `TcpOverUdpServer` destroys line state and finishes both directions.

If the service-facing side finishes, `TcpOverUdpServer` sends a close frame over KCP, flushes KCP output, destroys line state, and finishes the previous side.

Idle handling is the same basic model as the client side:

- after `ping-interval-ms` of no receive activity, a ping is sent if needed
- after `no-recv-timeout-ms` of no receive activity, the line is closed

### Backpressure behavior

If the KCP send queue grows beyond `kcp-send-buffer-limit`, `TcpOverUdpServer` schedules a pause toward the next side. When that setting is `0`, the limit is derived from the current KCP windows. When queued KCP data drops back below the threshold, it schedules resume.

## Notes And Caveats

- `TcpOverUdpServer` is intended to be paired with `TcpOverUdpClient`.
- FEC must be enabled on both peers with matching shard settings.
- The previous node should preserve packet boundaries.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.
