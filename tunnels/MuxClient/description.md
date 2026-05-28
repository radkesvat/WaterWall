# MuxClient Node

`MuxClient` multiplexes many logical WaterWall lines onto a smaller number of shared transport lines. Instead of opening one full transport connection for every child line, it opens a parent connection and packs multiple child streams into framed messages on that parent.

In practice, this node is used together with `MuxServer` on the remote side.

## What It Does

- Accepts many child lines from the previous node.
- Reuses a shared parent transport line toward the next node.
- Wraps child traffic into an internal MUX frame format.
- Creates a new parent transport line when the current one is exhausted.
- Demultiplexes reply frames from the remote `MuxServer` back to the correct child line.
- Forwards `pause`, `resume`, and `finish` per child stream.

This node is not a listener by itself. It relies on the previous node to create child lines and on the next node to provide the real shared transport.

## Typical Placement

A common layout is:

- some line-producing node before `MuxClient`
- `MuxClient`
- one transport chain after it
- `MuxServer` on the remote side of that transport
- service-facing nodes after `MuxServer`

Typical pairings are useful when you want many short or medium-lived logical connections to share fewer outer transport connections.

## Configuration Example

Timer mode:

```json
{
  "name": "mux-client",
  "type": "MuxClient",
  "settings": {
    "mode": "timer",
    "connection-duration": 30000
  },
  "next": "outbound-transport"
}
```

Counter mode:

```json
{
  "name": "mux-client",
  "type": "MuxClient",
  "settings": {
    "mode": "counter",
    "connection-capacity": 128
  },
  "next": "outbound-transport"
}
```

Fixed connection count mode:

```json
{
  "name": "mux-client",
  "type": "MuxClient",
  "settings": {
    "mode": "fixed-connections-count",
    "per-worker-connections-count": 2
  },
  "next": "outbound-transport"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"MuxClient"`.

- `next` `(string)`
  The next node that carries the shared parent transport connection.

### `settings`

- `mode` `(string)`
  Controls when `MuxClient` stops attaching new child lines to the current parent transport line.

  Supported values:
  - `"timer"`
  - `"counter"`
  - `"fixed-connections-count"`

- `connection-duration` `(integer, milliseconds)`
  Required when `mode` is `"timer"`.

  A parent transport line may accept new child lines only until this many milliseconds have passed since that parent was created.

  The implementation requires this value to be greater than `60`.

- `connection-capacity` `(integer)`
  Required when `mode` is `"counter"`.

  Maximum number of child streams that may be opened on one parent transport line before `MuxClient` rotates to a new
  parent.

  This value must be greater than `0`.

- `per-worker-connections-count` `(integer)`
  Required when `mode` is `"fixed-connections-count"`.

  Number of parent transport lines `MuxClient` keeps available per worker.

  This value must be greater than `0`.

## Optional `settings` Fields

- `child-buffer-limit` `(integer, bytes, optional)`
  Maximum queued data per paused child line before `MuxClient` locally pauses the parent mux input.

  Default: `8388608` (`8 MB`).

- `child-buffer-pause-tolerance` `(integer, bytes, optional)`
  Minimum queued data for a paused child line before `MuxClient` sends that child's `FlowPause` frame to the peer.

  Default: `524288` (`512 KB`). Set to `0` for immediate per-child pause frames. Values above `child-buffer-limit`
  are capped to `child-buffer-limit`.

## Detailed Behavior

### Parent and child model

`MuxClient` keeps two kinds of lines:

- child lines: the logical streams coming from the previous node
- parent lines: the shared transport connections opened toward the next node

Each child line gets a 32-bit connection id (`cid`). That id is used inside MUX frames so the remote `MuxServer` can map traffic back to the correct child stream.

In timer and counter modes, `MuxClient` keeps one current reusable parent line per worker. The code calls this the unsatisfied line. As long as that parent is still allowed to accept more children, new child lines will join it.

In fixed connection count mode, `MuxClient` keeps a fixed-size parent pool per worker. When a worker first needs a mux parent, it opens `per-worker-connections-count` parent transport lines for that worker. New child lines are assigned to the least-loaded parent in that worker's pool, with a round-robin tie break, and no additional parent lines are opened while the pool slots are alive.

### When a new parent connection is opened

When a child line arrives:

- if there is no reusable parent line for that worker, a new parent line is created
- if the current parent line is exhausted, a new parent line is created
- the new parent line is initialized through the next node
- the child line is then attached to that parent and an internal `Open` frame is sent

Once the `Open` frame is sent successfully, `MuxClient` immediately reports downstream establishment to the child line.

In fixed connection count mode, the first child on a worker creates that worker's fixed parent pool. Later child lines reuse those parents instead of creating more. If a parent slot is closed by the transport side, a later child can recreate that slot, but the active pool size for the worker is still capped by `per-worker-connections-count`.

### Exhaustion rules

The current parent line becomes exhausted in one of these ways:

- timer mode: its age becomes greater than `connection-duration`
- counter mode: its opened child stream count reaches `connection-capacity`
- fixed connection count mode: parent lines are not exhausted by age or child count
- absolute hard limit: the parent connection id reaches `4294967295`

An exhausted parent line is not closed immediately. It simply stops accepting new child lines. Existing child streams continue using it until they finish.

When the parent is exhausted and its last child closes, `MuxClient` closes the parent transport line too. If a reusable
parent becomes exhausted while it has no active children, `MuxClient` closes it before replacing it with a new parent.

### Internal frame format

`MuxClient` and `MuxServer` share the same fixed header format:

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

Payload length is the framed data length after the header.

### Data flow direction

- Child to parent transport: previous node -> `MuxClient` -> next node
- Parent transport back to child: next node -> `MuxClient` -> previous node

For payload, `MuxClient` adds the 8-byte header before sending data on the parent line.

For replies, it reads complete frames from the parent line, looks up the child by `cid`, strips the header, and forwards the payload to that child.

### Pause and resume behavior

When a child line is paused or resumed by the previous node, `MuxClient` uses `FlowPause` and `FlowResume` frames for
that child's `cid`; pause frames may be delayed by `child-buffer-pause-tolerance`.

If writing parent-delivered data to a child causes that child to pause, `MuxClient` queues later data for that child.
It sends `FlowPause` to the remote peer once that child's pending queue reaches `child-buffer-pause-tolerance`. Queued
child data is flushed when the child resumes. A `FlowResume` is sent once the child's pending data drops below `512 KB`,
so the peer can begin sending before the queue is fully empty.

If one paused child's queue reaches `child-buffer-limit`, `MuxClient` pauses the parent mux input. It resumes the parent input after all child queues are below their configured limit, allowing other child streams to continue.

When the remote side pauses the shared parent line, `MuxClient` tries to pause the child that most recently wrote to that parent. If no recent writer is known, it pauses all attached children. Resume behaves similarly.

### Buffering and overflow handling

Replies from the parent transport are accumulated in a read stream until complete MUX frames are available.

Current overflow limit:

- `1 MB` buffered on the parent read stream

If that limit is exceeded, `MuxClient` closes the parent line and finishes all child lines attached to it.

## Notes And Caveats

- `MuxClient` is intended to be paired with `MuxServer`.
- `mode` is mandatory in the current implementation.
- `connection-duration` is only valid in timer mode.
- `connection-capacity` is only valid in counter mode.
- `per-worker-connections-count` is only valid in fixed connection count mode.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation, so this node is not meant to be used as a generic chain endpoint.
