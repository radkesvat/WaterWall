<!--
Documentation version: 110
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/MuxServer.mdx, and both files must keep the same documentation version.
-->

# MuxServer Node

`MuxServer` is the server-side peer of `MuxClient`. It receives one shared parent transport line carrying framed MUX traffic, creates child lines on demand when `Open` frames arrive, and forwards each child stream to the next node as if it were a normal independent line.

In practice, this node is used together with `MuxClient` on the other side of the transport.

## What It Does

- Accepts a parent transport line carrying MUX frames.
- Parses the internal MUX frame format.
- Creates one child line per logical stream requested by `MuxClient`.
- Forwards each child line to the next node.
- Wraps downstream replies from child lines back into MUX frames.
- Propagates per-child `pause`, `resume`, and `finish` events.

This node does not create a transport by itself. It expects its previous side to already provide the shared connection that carries MUX traffic.

## Typical Placement

A common layout is:

- a transport-facing node before `MuxServer`
- `MuxServer`
- one or more service-facing nodes after it

`MuxServer` should usually sit opposite a `MuxClient` that is sending the framed traffic.

## Configuration Example

```json
{
  "name": "mux-server",
  "type": "MuxServer",
  "settings": {
    "detached-buffer-limit": 268435456,
    "detached-child-limit": 12000
  },
  "next": "service-side-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"MuxServer"`.

- `next` `(string)`
  The next node that should receive the logical child lines created by this tunnel.

### `settings`

There are no required tunnel-specific settings in the current implementation.

## Optional `settings` Fields

- `child-buffer-limit` `(integer, bytes, optional)`
  Maximum queued data per paused child line before `MuxServer` closes that child stream.

  Default: `25165824` (`24 MB`).

- `child-buffer-pause-tolerance` `(integer, bytes, optional)`
  Queued-data backstop for sending a `FlowPause` frame for a paused child.

  `FlowPause` is normally sent as soon as the child's local write side pauses, before data is queued. This threshold
  covers any ordering edge where the peer has not yet been told to stop. Raising it does not normally delay peer
  throttling.

  Default: `524288` (`512 KB`). Values above `child-buffer-limit` are capped to `child-buffer-limit`.

- `child-buffer-resume-threshold` `(integer, bytes, optional)`
  Low-water mark for sending `FlowResume` after the local child becomes writable. The frame is sent once the retained
  child queue falls below this value, allowing the peer to restart before the queue is completely empty. It must be
  greater than `0`; values above `child-buffer-limit` are capped to `child-buffer-limit`.

  Default: `262144` (`256 KiB`). Raising it resumes the peer earlier and may reduce high-RTT throughput gaps, at the
  cost of weaker hysteresis and potentially more pause/resume cycling.

- `parent-buffer-limit` `(integer, bytes, optional)`
  Per-parent budget for child-destined data queued across all children. When a newly queued payload makes the total
  reach the budget, `MuxServer` closes the child with the largest queue. Equal-sized queues prefer the
  least-recently-active child. This releases the pressure without pausing unrelated streams on the shared parent.

  Default: `33554432` (`32 MB`). Set to `0` to disable the aggregate budget; `child-buffer-limit` still bounds each
  individual child. The value may intentionally be lower than `child-buffer-limit`.

  The limit applies to each parent independently. Approximate worst-case queued memory is therefore
  `parent-buffer-limit` multiplied by the number of accepted parent transport connections.

- `detached-buffer-limit` `(integer, bytes, optional)`
  Per-worker byte limit for blocked child queues retained after parent loss. The default depends on the global
  `misc.ram-profile`, as shown below. Reaching it aborts only the newly detached blocked child. Set to `0` to disable
  this aggregate bound.

- `detached-child-limit` `(integer, optional)`
  Per-worker count limit for blocked children retained after parent loss. The default depends on the global
  `misc.ram-profile`, as shown below. Reaching it aborts only the newly detached blocked child. Set to `0` to disable
  this aggregate bound.

  | RAM profile | Default detached bytes | Default detached children |
  | --- | ---: | ---: |
  | S1 (`minimal` / `ultralow`) | `33554432` (`32 MiB`) | `4096` |
  | S2 | `80740352` (`77 MiB`) | `5677` |
  | M1 (`client`) | `127926272` (`122 MiB`) | `7258` |
  | M2 (`client-larger`) | `174063616` (`166 MiB`) | `8838` |
  | L1 | `221249536` (`211 MiB`) | `10419` |
  | L2 (`server`, the global default) | `268435456` (`256 MiB`) | `12000` |

  Defaults are linearly interpolated over the six ordered RAM-profile tiers, with the byte limit rounded to the
  nearest whole MiB. An explicit setting overrides the profile-derived value independently for that limit.

- `log-main-line-stats` `(boolean, optional)`
  When `true`, each active parent transport line logs mux diagnostics every `5` seconds.

  The log keeps `parent-line-read-paused=no` for compatibility and also reports `parent-queued-bytes` and
  `children-close-pending`, along with `wid`, parent-line write pause state, child count, child read-pause count, and
  child write-pause count.
  Default: `false`.

## Detailed Behavior

### Parent and child model

`MuxServer` works with two kinds of lines:

- the parent line: the shared transport line that carries MUX frames from the previous node
- child lines: logical streams created by `MuxServer` when it receives `Open` frames

Each child line is keyed by the `cid` carried in the frame header.

When an `Open` frame arrives:

- `MuxServer` creates a new child line on the same worker
- initializes line state for that child
- links it to the parent line
- calls upstream `init` on the next node for that child line

After that, `Data`, `Pause`, `Resume`, and `Close` frames for the same `cid` are routed to that child.

### Internal frame format

`MuxServer` expects the same 8-byte header used by `MuxClient`:

- `length` `(uint16)`
- `flags` `(uint8)`
- `_pad1` `(uint8)`
- `cid` `(uint32)`

Header size: `8 bytes`

Frame flags:

- `0`: `Open`
- `1`: `Close`
- `2`: `FlowPause`
- `3`: `FlowResume`
- `4`: `Data`

### Data flow direction

- Parent transport to child: previous node -> `MuxServer` -> next node
- Child reply back to parent transport: next node -> `MuxServer` -> previous node

For incoming `Data` frames, `MuxServer` strips the 8-byte header and forwards the payload to the child line.

For replies coming back from a child, `MuxServer` adds the same header and sends the frame back on the parent line.

### Finish and close handling

If `MuxServer` receives a `Close` frame for a child:

- the `Close` remains ordered after all earlier queued `Data`
- queued data drains only while the next destination is writable
- if paused, the child remains addressable by `cid` until Resume empties the queue
- upstream Finish and owned-line destruction happen only at the empty-and-writable barrier

If a child finishes from the service-facing side, `MuxServer` sends a `Close` frame back on the parent line.

If the parent transport line itself finishes, its borrowed MUX state is destroyed immediately. Already accepted child
queues detach from it and drain independently under ordinary child Pause/Resume. `MuxServer` inventories these owned
detached children per worker, rejects new outbound child data, and finishes/destroys each child after its queue drains.
The two detached limits bound the per-worker residual backlog.

### Pause and resume behavior

Per-child `FlowPause` and `FlowResume` frames are forwarded to the matching child line.

If writing parent-delivered data to a child causes that child to pause, `MuxServer` queues later data for that child.
`FlowPause` is sent as soon as the local child write side pauses, before later data is queued for it. Queued data is
flushed when the child resumes. `FlowResume` is sent once the child's queue drops below
`child-buffer-resume-threshold`, allowing the peer to begin sending before the queue is completely empty.

Queue pressure does not pause reads on the parent transport. A parent is shared by every child, so a parent read pause
taken for one indefinitely blocked destination also prevents unrelated child frames from being demultiplexed. That is
global head-of-line blocking even though the other streams and the parent transport are healthy.

Pressure is bounded by closing a child instead. If one child's queue reaches `child-buffer-limit`, that child is closed.
If the total queued data reaches `parent-buffer-limit`, the actual largest queued child is closed; equal-size ties prefer
the least-recently-active child. The total was below the budget before the newest payload, and the largest queue is at
least as large as that payload, so one close returns the parent below budget in the normal accounting path.

If the parent transport is paused without a known recent writer, `MuxServer` pauses all child lines attached to that parent. Resume only clears parent-write pressure; a child that is still under peer `FlowPause` remains paused.

### Buffering and overflow handling

Incoming MUX bytes are buffered until a full frame is available.

Current overflow limit:

- `1 MB` buffered on the parent read stream

If that limit is exceeded, `MuxServer` discards the incomplete parent remainder, finishes the parent line toward the
previous side, and applies the same detached drain behavior to already parsed child queues.

## Notes And Caveats

- `MuxServer` is intended to be paired with `MuxClient`.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.
- Duplicate `Open` frames for an already existing `cid` are ignored.
- A service-side Finish or orderly worker shutdown may discard residual detached data. Worker shutdown forwards no
  queued Payload, even for a writable child, before closing every remaining owned child.
- The detached drain changes no MUX wire bytes or peer capability requirements.
