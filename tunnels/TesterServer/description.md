<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/tester-server.mdx, and both files must keep the same documentation version.
-->

# TesterServer Node

`TesterServer` is the synthetic chain-end peer for `TesterClient`. It verifies the deterministic request sequence that
arrives from upstream, then sends the deterministic response sequence back downstream on the same Waterwall line.

It is meant for validating tunnel correctness and data integrity, not for serving real application traffic.

## What It Does

- acts as a chain end and receives the synthetic test flow from the previous node
- initializes per-line state during upstream `Init`
- immediately reports downstream `Est` so the chain head can begin sending requests
- verifies the fixed `11`-chunk request sequence coming from upstream by default
- sends the fixed `11`-chunk response sequence back downstream by default
- aborts the process on any size, order, byte-pattern, or lifecycle mismatch
- in `packet-mode`, uses the worker packet line and never expects normal runtime `Finish`
- optionally wraps packet-mode request and response chunks in a synthetic IPv4 packet with configured source,
  destination, protocol, and TTL
- optionally builds deterministic TCP, UDP, or ICMP headers inside the synthetic IPv4 packet

## Request And Response Pattern

`TesterServer` uses the same deterministic chunk sizes and direction-specific byte pattern as `TesterClient`.
The pattern is keyed by the client-selected per-flow id carried in the first request byte, not by the server's local
worker id.

Current stream-mode chunk sizes are:

- `1`
- `2`
- `4`
- `32`
- `512`
- `1024`
- `4096`
- `32768`
- `32769`
- `1048576`
- `2097152`

Current packet-mode chunk sizes are:

- `1`
- `2`
- `4`
- `32`
- `64`
- `128`
- `256`
- `512`
- `1024`
- `1499`
- `1500`

Current `packet-ipv4` chunk sizes are:

- `21`
- `22`
- `24`
- `52`
- `84`
- `148`
- `276`
- `532`
- `1044`
- `1499`
- `1500`

When `packet-ipv4.transport` is `tcp`, `udp`, or `icmp`, the packet chunks include IPv4 plus transport headers and use
these sizes:

- `41`
- `42`
- `44`
- `52`
- `84`
- `148`
- `276`
- `532`
- `1044`
- `1499`
- `1500`

`chunk-count` can limit the active sequence to a prefix of these tables. When omitted, all `11` chunks are used.

## Typical Placement

`TesterServer` belongs at the end of a synthetic validation chain, for example:

- `TesterClient -> EncryptionClient -> EncryptionServer -> TesterServer`
- `TesterClient(packet-mode=true) -> PingClient -> Bridge`, paired with
  `TesterServer(packet-mode=true) -> PingServer -> Bridge`

`TesterServer` is normally the chain end. In `packet-mode`, it can also sit before another packet tunnel and receive
request packets through downstream callbacks, which is useful with `Bridge` pairs that intentionally invert direction.

## Configuration Example

Stream mode:

```json
{
  "name": "tester-server",
  "type": "TesterServer"
}
```

Packet mode:

```json
{
  "name": "tester-server",
  "type": "TesterServer",
  "settings": {
    "packet-mode": true
  }
}
```

Packet mode with synthetic IPv4 packets:

```json
{
  "name": "tester-server",
  "type": "TesterServer",
  "settings": {
    "packet-mode": true,
    "packet-init-on-start": true,
    "packet-ipv4": {
      "source-ip": "198.51.100.10",
      "dest-ip": "203.0.113.20",
      "protocol": 253,
      "ttl": 64
    }
  }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TesterServer"`.

## Optional `settings`

- `packet-mode` `(boolean)`
  When `false` or omitted, `TesterServer` behaves like a normal stream chain end and expects the upstream side to close
  after the full response has been sent.
  Default: `false`

  When `true`, `TesterServer` runs on the worker packet line. In this mode:

  - the chain must already contain a packet-layer node so packet lines exist
  - each verified request packet produces one deterministic response packet
  - the worker packet line remains alive for the lifetime of the chain
  - receiving normal runtime `Finish` on that packet line is treated as a bug

- `packet-init-on-start` `(boolean)`
  Only meaningful when `packet-mode=true`.
  When `true`, `TesterServer` initializes its packet-line state once per worker during tunnel startup if it has not
  already been initialized by an upstream packet-line `Init`.
  Default: `false`

- `streaming-response` `(boolean)`
  Only meaningful in normal stream mode.
  When `false`, the full deterministic response sequence is held back until the full request sequence has been
  verified.
  Default: `false`

  When `true`, response chunks become eligible to send as soon as the matching request chunks are verified. This is
  useful for validating bidirectional transports where the response must overlap the request.

- `packet-stateless` `(boolean)`
  Only meaningful when `packet-mode=true`.
  When `true`, packet-mode requests may arrive out of order or as a subset of the full sequence. The server identifies
  the request chunk by packet size, verifies the deterministic payload, and sends the matching response packet.
  Default: `false`

- `chunk-count` `(integer)`
  Limits the request and response sequence to the first N documented chunks for the selected mode.
  Default: `11`

- `max-payload-size` `(integer)`
  When greater than `0` in stream mode, caps each generated downstream response payload buffer to this many bytes while
  still sending the full logical response sequence. This should match the client's cap when a stream-mode tester pair is
  intentionally placed over a datagram tunnel.

  In packet mode, this caps the generated packet chunk size instead of splitting packets. The cap must still leave room
  for the configured packet headers. This option is not supported with `packet-stateless=true` because stateless packet
  verification identifies chunks by packet size.
  Default: `0` (use the large buffer size)

- `split-payload-delay-ms` `(integer)`
  Non-negative delay between stream-mode split response payload buffers when `max-payload-size` is active.
  Use `0` for immediate queued scheduling only with transports that can tolerate the resulting burst.
  Default: `1`

- `split-payload-burst` `(integer)`
  Number of stream-mode split response payload buffers to send before applying `split-payload-delay-ms`.
  Default: `1`

- `packet-ipv4` `(object)`
  Optional synthetic IPv4 envelope mode for `packet-mode`.
  When present, each packet-mode request and response chunk is treated as a complete IPv4 packet instead of opaque
  packet payload bytes.

  Required child fields:
  - `source-ip` `(string)`
    Required IPv4 source address for request packets arriving from upstream. Response packets use the reverse direction
    automatically.
  - `dest-ip` `(string)`
    Required IPv4 destination address for request packets arriving from upstream. Response packets use the reverse
    direction automatically.

  Optional child fields:
  - `transport` `(string)`
    Optional transport header to generate and verify inside the IPv4 packet.
    Supported values: `tcp`, `udp`, `icmp`, `raw`, `none`.
    When set to `tcp`, `udp`, or `icmp`, the IPv4 protocol number is derived from the transport. If `protocol` is also
    present, it must match that transport.
    Default: `none`
  - `protocol` `(integer)`
    IPv4 protocol number written into synthetic response headers and required again during request verification.
    Default: `253`
  - `ttl` `(integer)`
    IPv4 TTL written into synthetic response headers.
    Default: `64`

## Detailed Behavior

### Init and establishment flow

On upstream `Init`, `TesterServer`:

- initializes its per-line state immediately
- sends downstream `Est` toward the previous tunnel

That downstream `Est` is the signal `TesterClient` uses to start transmitting request chunks.

### Request verification

Upstream payload is treated as the request side of the integrity test.

In stream mode:

- incoming buffers are staged in a `buffer_stream_t`
- the tunnel reads complete expected request chunks in order
- trailing bytes after the full expected request sequence are treated as failure
- once the full request is verified, the response side becomes ready to send

In packet mode:

- each packet payload must match exactly one expected request chunk
- when `packet-ipv4` is enabled, that packet must be a complete non-fragmented IPv4 packet with the configured
  protocol and the expected source and destination addresses for that direction
- after a request packet is verified, a response packet for the same chunk index is queued
- downstream response sending is scheduled on the line worker loop so request verification can complete cleanly first

### Response send and backpressure

Responses always go back on the downstream path with `tunnelPrevDownStreamPayload()`.

In stream mode:

- with `streaming-response=false`, all response chunks are sent only after the full request sequence is verified
- with `streaming-response=true`, response chunks are sent in order as request verification advances
- upstream `Pause` and `Resume` toggle response sending for backpressure

In packet mode:

- one deterministic response packet is created per verified request packet
- queued response packets are drained while not paused
- completion is reached only after all expected request packets were verified and all queued responses were sent

### Finish behavior

In stream mode, normal success does not require `TesterServer` to send any `Finish` back toward the previous tunnel.
If an upstream `Finish` does arrive after full request verification and after the full response sequence has already been
sent, `TesterServer` only destroys its own per-line state locally.

If upstream `Finish` arrives too early, it is treated as a failure. In packet mode, upstream `Finish` is treated as a
bug because packet lines are shared worker state, not per-connection lines.

## Notes And Caveats

- `TesterServer` is a synthetic validation tunnel, not a listener or transport connector
- downstream callbacks remain disabled in normal stream mode
- in packet mode, downstream `Init`/`Payload`/`Pause`/`Resume` are supported so a bridged packet path can feed
  requests into `TesterServer` from the next side and receive responses back upstream
- in packet mode, `TesterServer` now generates the deterministic response pattern instead of merely reflecting request
  bytes, so both directions are validated consistently
- in `packet-ipv4` mode the documented chunk sizes include packet headers, so the verified synthetic payload body is
  `chunk-size - IPv4 header length` in raw mode, or `chunk-size - IPv4 header length - transport header length` when
  `transport` is enabled
- in packet mode, `max-payload-size` reduces the effective chunk size before packet generation; it does not split one
  logical packet into multiple packets
