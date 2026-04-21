# TesterServer Node

`TesterServer` is the synthetic chain-end peer for `TesterClient`. It verifies the deterministic request sequence that
arrives from upstream, then sends the deterministic response sequence back downstream on the same Waterwall line.

It is meant for validating tunnel correctness and data integrity, not for serving real application traffic.

## What It Does

- acts as a chain end and receives the synthetic test flow from the previous node
- initializes per-line state during upstream `Init`
- immediately reports downstream `Est` so the chain head can begin sending requests
- verifies the fixed `11`-chunk request sequence coming from upstream
- sends the fixed `11`-chunk response sequence back downstream
- aborts the process on any size, order, byte-pattern, or lifecycle mismatch
- in `packet-mode`, uses the worker packet line and never expects normal runtime `Finish`

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
- `16777216`
- `33554432`

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

## Typical Placement

`TesterServer` belongs at the end of a synthetic validation chain, for example:

- `TesterClient -> EncryptionClient -> EncryptionServer -> TesterServer`
- `TesterClient(packet-mode=true) -> PingClient -> PingServer -> TesterServer(packet-mode=true)`

`TesterServer` must be the chain end.

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
- after a request packet is verified, a response packet for the same chunk index is queued
- downstream response sending is scheduled on the line worker loop so request verification can complete cleanly first

### Response send and backpressure

Responses always go back on the downstream path with `tunnelPrevDownStreamPayload()`.

In stream mode:

- once the full request sequence is verified, all response chunks are sent in order
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
- `DownStreamInit`, `DownStreamEst`, `DownStreamPayload`, `DownStreamPause`, `DownStreamResume`, and
  `DownStreamFinish` are intentionally disabled because this node is a chain end
- in packet mode, `TesterServer` now generates the deterministic response pattern instead of merely reflecting request
  bytes, so both directions are validated consistently
