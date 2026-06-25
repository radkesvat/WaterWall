# SpeedTestClient Node

`SpeedTestClient` is a synthetic chain-head bandwidth test tunnel. It creates normal WaterWall lines, sends framed
speed-test traffic into the next tunnel, validates frames received back from the server, and prints interval and final
throughput reports.

It is meant for measuring a WaterWall chain or transport path. It does not open sockets itself and it is not a packet
line tunnel. Pair it with `SpeedTestServer` on the other side of a TCP or UDP transport.

## What It Does

- acts as a chain head and creates the test lines itself
- starts `connection-count` independent normal lines during tunnel startup
- sends an upstream `Init` to the next tunnel for each generated line
- waits for downstream `Est` before sending speed-test frames
- sends a protocol `HELLO`, optional upload `DATA`, `END`, and expects server reports
- optionally receives download `DATA` from the server and validates the deterministic payload pattern
- prints interval sender/receiver reports and an aggregate final summary
- exits WaterWall when all streams complete unless `terminate-on-complete=false`

## Typical Placement

`SpeedTestClient` must be the first node in its chain. It sends generated traffic upstream to the configured transport:

- `SpeedTestClient -> TcpConnector`
- `SpeedTestClient -> UdpConnector`
- `SpeedTestClient -> TlsClient -> TcpConnector`
- `SpeedTestClient -> EncryptionClient -> TcpConnector`

The remote side should normally be:

- `TcpListener -> SpeedTestServer`
- `UdpListener -> SpeedTestServer`
- `TcpListener -> TlsServer -> SpeedTestServer`
- `TcpListener -> EncryptionServer -> SpeedTestServer`

## TCP Example

Client side:

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
      "report-interval-ms": 1000,
      "connection-count": 4,
      "payload-size": 131072,
      "terminate-on-complete": true
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
      "json-summary": true
    }
  }
]
```

## UDP Example

Client side:

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
      "report-interval-ms": 1000,
      "payload-size": 3800,
      "udp-target-bits-per-sec": 10000000,
      "terminate-on-complete": true
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
    "type": "SpeedTestServer"
  }
]
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"SpeedTestClient"`.

- `next` `(string)`
  The next node that should receive the generated speed-test lines.

## Optional `settings`

- `mode` `(string)`
  Transport framing mode. Supported values:
  - `"tcp"`: stream mode. Frames are read from a byte stream.
  - `"udp"`: datagram mode. Each WaterWall payload buffer is one speed-test frame.

  Default: `"tcp"`

- `direction` `(string)`
  Test direction. Supported values:
  - `"upload"` or `"send"`: client sends data, server receives and reports.
  - `"download"` or `"receive"`: server sends data, client receives and reports.
  - `"bidirectional"` or `"both"`: both sides send and receive at the same time.

  Default: `"upload"`

- `duration-ms` `(integer)`
  Measured test duration after warmup.
  Default: `10000`

- `warmup-ms` `(integer)`
  Time before the measured interval starts. Warmup data is sent and validated but excluded from byte totals.
  Default: `0`

- `report-interval-ms` `(integer)`
  Interval report cadence.
  Default: `1000`

- `start-delay-ms` `(integer)`
  Delay before each generated line is started after tunnel startup.
  Default: `50`

- `timeout-ms` `(integer)`
  Watchdog timeout for each generated stream. Must be greater than `warmup-ms + duration-ms`.
  Default: `warmup-ms + duration-ms + 30000`

- `connection-count` `(integer)`
  Number of parallel WaterWall lines to create.
  Default: `1`

- `payload-size` `(integer)`
  Data bytes inside each speed-test `DATA` frame, excluding the `48` byte protocol header.
  Defaults:
  - TCP: `131072`
  - UDP: `3800`

  Maximum:
  - TCP: `16777216`
  - UDP: `64952`

- `target-bits-per-sec` `(number)`
  Optional sender pacing rate in bits per second.
  Default: `0` in TCP mode, meaning send as fast as backpressure allows.

- `udp-target-bits-per-sec` `(number)`
  UDP-specific pacing rate in bits per second.
  Default: `10000000` in UDP mode.

- `target-megabits-per-sec` `(number)`
  Alternative pacing field expressed in megabits per second.

  Only one of `target-bits-per-sec`, `udp-target-bits-per-sec`, and `target-megabits-per-sec` may be configured.

- `json-summary` `(boolean)`
  Prints a compact final JSON-style summary in addition to normal logs.
  Default: `false`

- `terminate-on-complete` `(boolean)`
  Exits WaterWall after all streams finish. Exit code is `0` when all streams succeeded and `1` if any stream failed.
  Default: `true`

## Detailed Behavior

### Startup and line creation

On start, `SpeedTestClient` schedules one startup task per requested stream. Each task:

- chooses a worker by `stream_id % workers_count`
- creates a normal WaterWall line on that worker
- initializes this tunnel's per-line state
- sends upstream `Init` to the next tunnel
- arms a watchdog for the configured timeout

The tunnel owns those generated lines and destroys them after the test completes or fails.

### Establishment and HELLO

After downstream `Est`, the client sends a `HELLO` frame that tells the server:

- protocol mode
- requested direction
- duration and warmup
- report interval
- payload size
- target bandwidth
- total stream count
- stream id

In UDP mode, the client waits for the server `ACK` before sending data. While waiting, it retransmits `HELLO` at a short
interval so a lost datagram does not stall the test.

### Data and reports

Upload data is sent upstream as `DATA` frames. Download data is received downstream from the server. Payload bytes use a
deterministic pattern keyed by stream id, sequence number, and direction.

The receiver tracks:

- bytes
- packets
- valid packets
- lost packets
- duplicate packets
- out-of-order packets
- validation errors
- jitter estimate

At the end of each direction, the sender sends an `END` frame. The server sends final `REPORT` frames for upload and/or
download. The client completes a stream only after all expected final reports are received.

## Notes And Caveats

- `SpeedTestClient` creates normal connection lines. It does not use packet lines.
- UDP mode measures datagram delivery. Loss, duplicates, and reordering are reported instead of hidden.
- TCP mode has no default pacing and can send as fast as the chain and socket backpressure allow.
- `payload-size` is speed-test payload bytes; the on-wire WaterWall payload also includes a `48` byte speed-test frame
  header.
- The tunnel is a benchmark/test generator, not an application proxy.
