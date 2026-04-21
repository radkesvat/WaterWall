# TesterClient Node

`TesterClient` is a synthetic chain-head test tunnel. It creates one test flow per worker, sends a deterministic
request sequence into the chain, verifies the deterministic response sequence that comes back, and aborts the process on
any mismatch or timeout.

It is meant for validating tunnel composition and payload integrity, not for production traffic.

## What It Does

- acts as a chain head and creates the test lines itself
- waits `50 ms` after startup before creating one worker-local test line per chain worker
- initializes per-line state in `Init`, then drives the request side only after downstream `Est`
- sends `11` fixed-size request chunks upstream
- verifies `11` fixed-size response chunks coming back downstream
- fails fast on any size, order, byte-pattern, or timeout mismatch
- in normal stream mode, logs success after the full response is verified and exits the program once all workers complete
- in `packet-mode`, reuses the worker packet line and never expects normal runtime `Finish`

## Request And Response Pattern

The tunnel uses deterministic payload sizes and deterministic byte patterns derived from:

- chunk index
- byte offset inside the chunk
- per-flow test id
- direction (`request` versus `response`)

The first request byte carries that per-flow id so a real transport hop can remap the connection onto a different
worker without breaking verification.

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

Stream mode is usually placed at the start of a synthetic end-to-end test chain, for example:

- `TesterClient -> EncryptionClient -> EncryptionServer -> TesterServer`
- `TesterClient -> TlsClient -> TcpConnector -> ... -> TesterServer`

Packet mode is for packet-layer test chains where worker packet lines already exist, for example:

- `TesterClient(packet-mode=true) -> PingClient -> PingServer -> TesterServer(packet-mode=true)`

`TesterClient` must be the chain head.

## Configuration Example

Stream mode:

```json
{
  "name": "tester-client",
  "type": "TesterClient",
  "next": "next-node-name"
}
```

Packet mode:

```json
{
  "name": "tester-client",
  "type": "TesterClient",
  "settings": {
    "packet-mode": true
  },
  "next": "packet-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TesterClient"`.

- `next` `(string)`
  The next node that should receive the synthetic test line or packet line.

## Optional `settings`

- `packet-mode` `(boolean)`
  When `false` or omitted, `TesterClient` creates a normal stream `line_t` on each worker and expects normal
  Waterwall `Est -> Payload -> Finish` behavior.
  Default: `false`

  When `true`, `TesterClient` uses the chain worker packet line instead of creating a stream line. In this mode:

  - the chain must already contain a packet-layer node so packet lines exist
  - the worker packet line is initialized once at startup
  - no normal runtime `Finish` is expected on that packet line
  - the small buffer pool must provide at least `1500` bytes of writable payload capacity

## Detailed Behavior

### Startup and line creation

On tunnel start, `TesterClient` schedules one startup task per chain worker. Each worker task:

- picks the worker packet line when `packet-mode` is enabled, otherwise creates a fresh normal line
- initializes this tunnel's per-line state immediately
- sends upstream `Init` to the next tunnel while holding a temporary line reference
- arms a `30000 ms` watchdog for that worker line

### Establishment and request send

`TesterClient` waits for downstream `Est` before it starts sending requests.

After `Est`:

- the line is marked established if needed
- request sending is scheduled onto the line's worker loop
- request chunks are sent in order on the upstream path
- downstream `Pause` and `Resume` toggle request sending for backpressure

### Response verification

Downstream payload is treated as the response side of the integrity test.

In stream mode:

- buffers are staged in a `buffer_stream_t`
- each complete expected chunk is read and verified in order
- trailing bytes after the expected sequence are treated as failure
- once verification completes, that worker is marked successful

In packet mode:

- each incoming packet payload must match exactly one expected response chunk
- extra packets, early packets, or wrong-size packets are treated as failure
- successful completion marks the worker packet line test as done without closing the packet line

### Finish behavior

In stream mode, normal success does not depend on a FIN exchange. `TesterClient` succeeds as soon as it has verified the
full response sequence for every worker and then terminates the program with exit code `0`.

If downstream `Finish` does arrive before full response verification, it is treated as a failure. In packet mode,
downstream `Finish` is also considered a bug because worker packet lines are runtime-persistent helper lines, not
closable connection lines.

## Notes And Caveats

- `TesterClient` is a synthetic validation tunnel, not a transport adapter.
- the watchdog currently aborts the process if a worker line does not complete within `30000 ms`
- `TesterClient` keeps one completion slot per worker and currently supports at most `254` chain workers
- `UpStreamInit`, `UpStreamEst`, `UpStreamPayload`, `UpStreamPause`, `UpStreamResume`, and `UpStreamFinish` are
  intentionally disabled because this node is a chain head
