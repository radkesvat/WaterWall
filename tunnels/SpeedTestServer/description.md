# SpeedTestServer Node

`SpeedTestServer` is the chain-end peer for `SpeedTestClient`. It accepts speed-test frames from upstream, validates
upload data, optionally sends download data back downstream, and returns final sender/receiver reports to the client.

It is a normal connection-oriented tunnel. It does not create lines, it does not own line destruction, and it is not a
packet-line tunnel.

## What It Does

- acts as a chain end for a `SpeedTestClient` flow
- initializes per-line state during upstream `Init`
- immediately sends downstream `Est` so the client can start the test
- accepts the client's `HELLO` and replies with `ACK`
- validates upload `DATA` frames from the client
- optionally sends download `DATA` frames to the client
- sends final `REPORT` frames for completed upload and download directions
- closes the downstream side after the test is complete or after a protocol failure

## Typical Placement

`SpeedTestServer` must be the last node in its chain. It receives speed-test traffic from a listener or from any protocol
decapsulation stack in front of it:

- `TcpListener -> SpeedTestServer`
- `UdpListener -> SpeedTestServer`
- `TcpListener -> TlsServer -> SpeedTestServer`
- `TcpListener -> EncryptionServer -> SpeedTestServer`

The client side should normally be:

- `SpeedTestClient -> TcpConnector`
- `SpeedTestClient -> UdpConnector`
- `SpeedTestClient -> TlsClient -> TcpConnector`
- `SpeedTestClient -> EncryptionClient -> TcpConnector`

## TCP Example

Server side:

```json
[
  {
    "name": "speedtest-listener",
    "type": "TcpListener",
    "settings": {
      "address": "0.0.0.0",
      "port": 9000,
      "nodelay": true
    },
    "next": "speedtest-server"
  },
  {
    "name": "speedtest-server",
    "type": "SpeedTestServer",
    "settings": {
      "report-interval-ms": 1000,
      "json-summary": true,
      "quiet": false
    }
  }
]
```

Matching client side:

```json
[
  {
    "name": "speedtest-client",
    "type": "SpeedTestClient",
    "settings": {
      "mode": "tcp",
      "direction": "bidirectional",
      "duration-ms": 10000,
      "warmup-ms": 1000,
      "connection-count": 4,
      "payload-size": 131072
    },
    "next": "speedtest-out"
  },
  {
    "name": "speedtest-out",
    "type": "TcpConnector",
    "settings": {
      "address": "198.51.100.10",
      "port": 9000,
      "nodelay": true
    }
  }
]
```

## UDP Example

Server side:

```json
[
  {
    "name": "speedtest-udp-listener",
    "type": "UdpListener",
    "settings": {
      "address": "0.0.0.0",
      "port": 9001
    },
    "next": "speedtest-server"
  },
  {
    "name": "speedtest-server",
    "type": "SpeedTestServer",
    "settings": {
      "report-interval-ms": 1000
    }
  }
]
```

Matching client side:

```json
[
  {
    "name": "speedtest-client",
    "type": "SpeedTestClient",
    "settings": {
      "mode": "udp",
      "direction": "upload",
      "duration-ms": 10000,
      "warmup-ms": 1000,
      "payload-size": 1200,
      "udp-target-bits-per-sec": 10000000
    },
    "next": "speedtest-udp-out"
  },
  {
    "name": "speedtest-udp-out",
    "type": "UdpConnector",
    "settings": {
      "address": "198.51.100.10",
      "port": 9001
    }
  }
]
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"SpeedTestServer"`.

`SpeedTestServer` is a chain end and must not have a `next` node.

## Optional `settings`

- `report-interval-ms` `(integer)`
  Fallback interval log cadence before a client `HELLO` is received. After `HELLO`, the client's requested report
  interval is used for that line.
  Default: `1000`

- `json-summary` `(boolean)`
  Default value for JSON-style per-stream summaries. A client `HELLO` with `json-summary` enabled can also request this
  per line.
  Default: `false`

- `quiet` `(boolean)`
  Suppresses SpeedTestServer runtime logs, including accepted-stream, interval, final summary, and per-stream failure
  messages. Fatal configuration or invalid-chain diagnostics may still be logged.
  Default: `false`

## Detailed Behavior

### Init and establishment

On upstream `Init`, `SpeedTestServer`:

- initializes its per-line state
- creates a stream buffer for TCP-mode framing
- sends downstream `Est` to the previous tunnel

The downstream `Est` is the signal used by `SpeedTestClient` to begin its HELLO and data schedule.

### HELLO and ACK

The first client frame must be a `HELLO`. It configures the server's per-line behavior:

- `tcp` or `udp` mode
- upload, download, or bidirectional direction
- duration and warmup
- report interval
- payload size
- target bandwidth
- total stream count and stream id

After accepting the `HELLO`, the server sends an `ACK` downstream. In UDP mode, duplicate `HELLO` frames are answered
with another `ACK` so a lost ACK does not leave the client waiting forever.

### Upload receive path

When upload is enabled, upstream `DATA` frames are validated using the deterministic pattern generated by
`SpeedTestClient`.

The server tracks:

- bytes
- packets
- valid packets
- lost packets
- duplicate packets
- out-of-order packets
- validation errors
- jitter estimate

When the client sends upload `END`, the server sends a receiver `REPORT` downstream.

### Download send path

When download is enabled, the server schedules downstream `DATA` frames after `HELLO` is accepted. It uses the same
payload size, warmup, duration, and optional target bandwidth requested by the client.

At the end of the download interval, the server sends:

- download `END`
- sender `REPORT`

The line closes only after every requested direction has finished and every required report has been sent.

### Stream and datagram framing

In TCP mode, incoming bytes are accumulated in a `buffer_stream_t` and decoded as speed-test frames. Oversized or
malformed frame lengths fail the line instead of allowing unbounded buffering.

In UDP mode, each WaterWall payload buffer must contain exactly one speed-test frame. The server does not treat UDP
payloads as a byte stream.

### Finish behavior

If upstream closes before a complete test, the server destroys only its own per-line state. It does not destroy the
`line_t`, because that line was created by the listener or another upstream adapter.

When the server completes or fails a test itself, it:

- sends any final protocol bytes that are still required
- destroys its own line state
- forwards downstream `Finish`

## Notes And Caveats

- `SpeedTestServer` is only useful with a matching `SpeedTestClient`.
- It is a chain end and its downstream entry callbacks are intentionally disabled.
- It stores per-line state for normal connection lines only. It does not operate on WaterWall packet lines.
- UDP mode reports packet loss and reordering; it does not retry data frames.
- The server trusts the client to choose the test shape, but validates payload sizes and frame types before buffering or
  processing them.
