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
  "settings": {},
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

  Default: `8388608` (`8 MB`).

- `child-buffer-pause-tolerance` `(integer, bytes, optional)`
  Queued-data threshold where a paused child also pauses reads on the shared parent transport.

  Default: `524288` (`512 KB`). Set to `0` to pause parent reads as soon as data must be queued for a paused child.
  Values above `child-buffer-limit` are capped to `child-buffer-limit`.

- `log-main-line-stats` `(boolean, optional)`
  When `true`, each active parent transport line logs mux diagnostics every `5` seconds.

  The log includes `wid`, parent-line write/read pause state, child count, child read-pause count, and child
  write-pause count. Default: `false`.

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

- the child is detached from the parent
- child line state is destroyed
- upstream finish is sent to the next node
- the child line is destroyed

If a child finishes from the service-facing side, `MuxServer` sends a `Close` frame back on the parent line.

If the parent transport line itself finishes, `MuxServer` closes all currently attached child lines too.

### Pause and resume behavior

Per-child `FlowPause` and `FlowResume` frames are forwarded to the matching child line.

If writing parent-delivered data to a child causes that child to pause, `MuxServer` queues later data for that child.
`FlowPause` is sent as soon as the local child write side pauses. If the queued data reaches
`child-buffer-pause-tolerance`, `MuxServer` also pauses parent transport reads locally so the shared parent cannot keep
draining into that child's queue. Queued child data is flushed when the child resumes. A `FlowResume` is sent once the
child's pending data drops below `512 KB`, so the peer can begin sending before the queue is fully empty; parent reads
resume when no child queue still requires the parent pause.

If one paused child's queue still reaches `child-buffer-limit`, `MuxServer` sends a `Close` for that child and finishes the local child line.

If the parent transport is paused without a known recent writer, `MuxServer` pauses all child lines attached to that parent. Resume only clears parent-write pressure; a child that is still under peer `FlowPause` remains paused.

### Buffering and overflow handling

Incoming MUX bytes are buffered until a full frame is available.

Current overflow limit:

- `1 MB` buffered on the parent read stream

If that limit is exceeded, `MuxServer` closes every child attached to that parent and finishes the parent line toward the previous side.

## Notes And Caveats

- `MuxServer` is intended to be paired with `MuxClient`.
- There are no tunnel-specific JSON settings today.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.
- Duplicate `Open` frames for an already existing `cid` are ignored.
