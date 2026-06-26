<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/SpeedLimit.mdx, and both files must keep the same documentation version.
-->

# SpeedLimit Node

`SpeedLimit` slows traffic down to a configured maximum rate.

It can be used in two broad styles:

- `pause` mode for stream-style chains such as TCP, where traffic should wait instead of being discarded
- `drop` mode for packet-style chains such as packet tunnels or UDP-style datagrams, where excess traffic may be thrown away

This tunnel does not change protocol data. It only decides how quickly payload is allowed to pass.

## What It Does

- Applies rate limit to payload crossing the tunnel
- Uses a token bucket, so traffic is released again as tokens refill over time
- Can keep a separate limit per line, one shared limit for the whole tunnel, or one shared limit per worker
- In `pause` work mode, buffers excess stream data and resumes later
- In `drop` work mode, discards whole payload chunks when there are not enough tokens

The configured limit applies to both directions combined for the selected bucket.

That means if one bucket is limited to `1 MB/s`, upload and download through that same bucket together share that `1 MB/s`.

## Work Mode

### Stream shaping

Use `pause` mode when you want traffic to wait:

- `TcpListener <--> SpeedLimit <--> TcpConnector`
- `TcpListener <--> SpeedLimit <--> TlsClient <--> TcpConnector`

### Packet dropping

Use `drop` mode when waiting is not the right behavior:

- `TunDevice <--> SpeedLimit <--> UdpStatelessSocket`
- packet or UDP-datagram chains where dropping is acceptable

## Configuration Example

### Per connection stream limit

```json
{
  "name": "speed-limit",
  "type": "SpeedLimit",
  "settings": {
    "kilo-bytes-per-sec": 256,
    "limit-mode": "per-line",
    "work-mode": "pause"
  },
  "next": "next-node"
}
```

### Global shared limit

```json
{
  "name": "global-speed-limit",
  "type": "SpeedLimit",
  "settings": {
    "mega-bytes-per-sec": 8,
    "limit-mode": "all-lines",
    "token-recharge-rate": 20,
    "work-mode": "pause"
  },
  "next": "next-node"
}
```

### Packet drop limit

```json
{
  "name": "packet-speed-limit",
  "type": "SpeedLimit",
  "settings": {
    "bytes-per-sec": 500000,
    "limit-mode": "per-worker",
    "work-mode": "drop"
  },
  "next": "next-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen node name.

- `type` `(string)`
  Must be exactly `"SpeedLimit"`.

### `settings`

`settings` must be a non-empty object.

## Required `settings` Fields

You must set exactly one speed field:

- `bytes-per-sec` `(number)`
- `kilo-bytes-per-sec` `(number)`
- `mega-bytes-per-sec` `(number)`

Only one of those three may appear at the same time.

You must also set:

- `limit-mode` `(string)`
- `work-mode` `(string)`



## `limit-mode`

- `per-connection`
- `per-line`

These mean the same thing.

Each Waterwall line gets its own token counter.

If you have two simultaneous lines and each line is limited to `1 MB/s`, together they may use about `2 MB/s`.

- `all-connections`
- `all-lines`

These also mean the same thing.

All lines through this tunnel instance share one token counter.

If the limit is `1 MB/s`, then all matching connections together share that `1 MB/s`.

- `per-worker`

Each worker thread gets its own shared counter.

If the limit is `1 MB/s` and Waterwall is running with `4` workers, the practical total cap can reach about `4 MB/s` overall, because each worker has its own `1 MB/s` bucket.

## `work-mode` Meanings

- `pause`

Use this for stream traffic where data should wait.

When the bucket is empty:

- payload is queued inside the tunnel
- the source side is paused with Waterwall backpressure callbacks
- queued data is released later as tokens refill

This is the right choice for TCP-style chains.

- `drop`

Use this for packet or datagram traffic where dropping is acceptable.

When the bucket is empty:

- the current payload chunk is discarded
- the tunnel does not queue it for later

This is the safer choice for packet tunnels and UDP-style traffic.

## Optional `settings` Fields

- `token-recharge-rate` `(integer)`
  Milliseconds between token recharges.

  Default: `10`

## How `token-recharge-rate` Works

This value is a time interval in milliseconds, not a bandwidth value.

Example:

- limit: `1000 bytes-per-sec`
- `token-recharge-rate`: `10`

Then the tunnel adds tokens every `10 ms`.

Smaller values:

- recharge more often
- usually feel smoother
- allow smaller bursts

Larger values:

- recharge less often
- can feel more bursty
- may release traffic in larger steps

## Detailed Behavior

### In `pause` mode

For stream traffic, `SpeedLimit` may release only part of a large queued buffer, then keep the rest queued until later.

This helps preserve ordering while still shaping the average speed.

When the queue becomes empty again, the tunnel resumes the paused source side.

### In `drop` mode

For packet-style traffic, `SpeedLimit` makes a whole-payload decision.

If there are not enough tokens for that packet or datagram chunk, it drops that chunk instead of sending part of it.

### Lifecycle behavior

- per-line state is created during `Init`
- in `pause` mode, drain timers are cancelled during line-state destruction
- `Finish` clears any queued payload owned by this tunnel before forwarding the Waterwall finish callback
- `required_padding_left` is `0`, because this tunnel does not prepend protocol bytes

## Notes And Caveats

- `pause` mode can temporarily hold extra data in memory while the sender waits.
- `drop` mode is usually the right choice for packet tunnels and UDP-style traffic.
- `per-worker` mode intentionally scales with worker count.
- `all-lines` mode is the best choice when you want one shared cap for the whole node.
- The limit is shared by both directions combined inside each selected bucket.
- In packet chains, Waterwall packet lines are worker-shared helper lines. Because of that, `per-line` on a packet line behaves like a worker-local shared bucket, not a separate limit for each packet flow.
