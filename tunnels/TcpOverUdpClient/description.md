<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TcpOverUdpClient.mdx, and both files must keep the same documentation version.
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

When a line is initialized, `TcpOverUdpClient` creates a KCP session, starts a periodic timer, and immediately queues an internal ping frame.

Stream payload arriving from the previous node is split into chunks small enough to fit into the configured KCP write MTU and then sent through KCP.

The remote `TcpOverUdpServer` performs the reverse operation and exposes the reconstructed stream again.

### Internal frame flags

Inside the KCP payload, this tunnel uses a 1-byte flag:

- `0x00`: data
- `0xF0`: ping
- `0xFF`: close

Data frames carry real stream bytes after the first byte.

Ping frames are only used as keepalive markers. Close frames request shutdown of the paired line.

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

The code also sets KCP MTU from `GLOBAL_MTU_SIZE` and uses an effective write payload size of roughly:

- `GLOBAL_MTU_SIZE - 20 - 8 - 24 - 1`

If FEC is enabled, the tunnel subtracts the FEC wire overhead from the outer KCP/UDP packet budget so the transport stays within the same path MTU envelope.

### Optional FEC layer

When `fec` is enabled, the tunnel wraps each outbound KCP datagram in a Reed-Solomon FEC packet and emits parity packets after each configured data-shard block.

On receive, it:

- accepts FEC-wrapped KCP datagrams
- feeds normal data packets into KCP immediately
- tries to recover missing KCP datagrams from parity packets
- drops invalid FEC packets conservatively

When `fec` is disabled, none of this extra framing is used and the node behaves exactly like the old KCP-only implementation.

### Data flow direction

- Stream to UDP/KCP side: previous node -> `TcpOverUdpClient` -> next node
- UDP/KCP side back to stream: next node -> `TcpOverUdpClient` -> previous node

On the send side, `TcpOverUdpClient` breaks the stream into KCP-friendly chunks and forwards the resulting packet traffic to the next node.

On the receive side, it feeds incoming packet payloads into KCP, drains completed KCP data, strips the 1-byte flag, and forwards reconstructed stream payload downstream to the previous node.

### Close and timeout behavior

If the previous side finishes, `TcpOverUdpClient` sends an internal close frame through KCP, flushes pending KCP output, destroys its line state, and finishes the next side.

If a close frame is received from the remote side, it destroys line state and finishes both directions.

If no data is received for too long:

- after `ping-interval-ms`, a ping is sent if one was not already sent
- after `no-recv-timeout-ms` without receive activity, the line is closed

### Backpressure behavior

If the KCP send queue grows beyond `kcp-send-buffer-limit`, `TcpOverUdpClient` schedules a pause toward the previous side. When that setting is `0`, the limit is derived from the current KCP windows. Once the KCP queue drains enough, it schedules a resume.

This is how the tunnel prevents unbounded growth while the packet path is congested.

## Notes And Caveats

- `TcpOverUdpClient` is intended to be paired with `TcpOverUdpServer`.
- FEC must be enabled on both peers with matching shard settings.
- The next node should preserve datagram boundaries.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.
