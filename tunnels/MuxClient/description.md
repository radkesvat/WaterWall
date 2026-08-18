<!--
Documentation version: 108
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/MuxClient.mdx, and both files must keep the same documentation version.
-->

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
    "connection-duration-ms": 30000
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

- `connection-duration-ms` `(integer, milliseconds)`
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
  Maximum queued data per paused child line before `MuxClient` closes that child stream.

  Default: `8388608` (`8 MB`).

- `child-buffer-pause-tolerance` `(integer, bytes, optional)`
  Queued-data backstop for sending a `FlowPause` frame for a paused child.

  In practice `FlowPause` is already sent the moment the child's write side pauses, which is before any data can be
  queued for it, so this threshold only covers the one case that ordering misses: a child paused before its `Open`
  frame reached the peer. Raising it does not delay peer throttling in any other flow.

  Default: `524288` (`512 KB`). Values above `child-buffer-limit` are capped to `child-buffer-limit`.

- `parent-buffer-limit` `(integer, bytes, optional)`
  Budget for the queued child data held across all children of one parent transport line. When the total reaches it,
  `MuxClient` closes the children holding the most queued data until the total is back under the budget.

  Default: `8388608` (`8 MB`). Set to `0` to remove the budget and bound memory by `child-buffer-limit` per child
  only. The value may deliberately sit below `child-buffer-limit`: whichever bound is reached first sheds.

  This is a per-parent figure, so the worst case a process can hold is `parent-buffer-limit` multiplied by the number
  of live parent lines - one per pool slot for `MuxClient`, one per accepted transport connection for `MuxServer`.
  Size it against the memory the host actually has, not against a single connection.

- `log-main-line-stats` `(boolean, optional)`
  When `true`, each active parent transport line logs mux diagnostics every `5` seconds.

  The log includes `wid`, parent-line write pause state, bytes queued on the parent, child count, child read-pause
  count, and child write-pause count. Default: `false`.

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

- timer mode: its age becomes greater than `connection-duration-ms`
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

`65,527` bytes is the maximum payload of one `Data` frame, not a limit on one
child `Payload` callback. The encoder splits a larger callback payload into
consecutive `Data` frames of at most `65,527` bytes and preserves the exact byte
order. The checked aggregate encoded size (payload plus every 8-byte frame
header and an optional `Open` frame) must fit in `uint32_t`. If it does not, the
input buffer is recycled and only that child is closed; no partial frame is
published. Allocation of the checked aggregate buffer follows the shift-buffer
fail-fast allocation contract, so an actual allocator refusal terminates rather
than forwarding a truncated encoding.

### Data flow direction

- Child to parent transport: previous node -> `MuxClient` -> next node
- Parent transport back to child: next node -> `MuxClient` -> previous node

For payload, `MuxClient` adds the 8-byte header before sending data on the parent line.

For replies, it reads complete frames from the parent line, looks up the child by `cid`, strips the header, and forwards the payload to that child.

### Pause and resume behavior

When a child line is paused or resumed by the previous node, `MuxClient` uses `FlowPause` and `FlowResume` frames for
that child's `cid`. `FlowPause` is sent as soon as the local child write side pauses.

If writing parent-delivered data to a child causes that child to pause, `MuxClient` queues later data for that child.
`FlowPause` for that `cid` has already been sent at the moment the child's write side paused, so the peer has
already been asked to stop producing for it; `child-buffer-pause-tolerance` is only a backstop for a child that
was paused before its `Open` frame reached the peer. Queued child data is flushed when the child resumes, and
a `FlowResume` is sent once the child's pending data drops below `512 KB`, so the peer can begin sending
before the queue is fully empty.

Queue pressure never pauses reads on the parent transport. The parent is shared by every child stream, so a pause taken
on behalf of one child could only be cleared by that same child draining. A child whose downstream peer has stopped
reading never drains, and while the parent is paused no frame can be read from it - not the peer's `FlowPause`
acknowledgement, not another child's reply - so nothing that could clear the pause is able to arrive. One stalled stream
would deadlock every stream multiplexed onto the same parent.

Pressure is relieved by shedding instead. If one paused child's queue reaches `child-buffer-limit`, `MuxClient` sends a
`Close` for that child and finishes the local child line. If the queued child data across the whole parent reaches
`parent-buffer-limit`, `MuxClient` closes the children holding the most queued data until the total is back under the
ceiling. Both bounds always terminate, because each close frees the queue that caused it.

When the remote side pauses the shared parent line, `MuxClient` tries to pause the child that most recently wrote to that parent. If no recent writer is known, it pauses all attached children. Resume only clears parent-write pressure; a child that is still under peer `FlowPause` remains paused.

### Buffering and overflow handling

Replies from the parent transport are accumulated in a read stream until complete MUX frames are available.

Current overflow limit:

- `1 MB` buffered on the parent read stream

If that limit is exceeded, `MuxClient` closes the parent line and finishes all child lines attached to it.

## Notes And Caveats

- `MuxClient` is intended to be paired with `MuxServer`.
- `mode` is mandatory in the current implementation.
- `connection-duration-ms` is only valid in timer mode.
- `connection-capacity` is only valid in counter mode.
- `per-worker-connections-count` is only valid in fixed connection count mode.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation, so this node is not meant to be used as a generic chain endpoint.
