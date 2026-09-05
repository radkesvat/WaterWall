<!--
Documentation version: 157
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/MuxClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/MuxClient.mdx, and all files must keep the same documentation version.
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

- `max-children` `(integer, optional)`
  Maximum concurrent live children on one parent. Default: `10000`. It must be
  positive and is separate from counter mode's cumulative
  `connection-capacity`.

- `child-buffer-limit` `(integer, bytes, optional)`
  Maximum retained `sbuf_t` allocation charge per paused child line before `MuxClient` closes that child stream.
  Each queued entry is charged by its actual capacity (including left padding), buffer header, and aligned-allocation
  overhead, rather than only by its application payload length.

  Default: `25165824` (`24 MB`).

- `child-buffer-pause-tolerance` `(integer, bytes, optional)`
  Logical queued-payload backstop for sending a `FlowPause` frame for a paused child.

  `FlowPause` is normally sent as soon as the child's local write side pauses, before data is queued. This threshold
  covers the ordering edge case where a child paused before its `Open` frame reached the peer. Raising it does not
  normally delay peer throttling.

  Default: `524288` (`512 KB`). Values above `child-buffer-limit` are capped to `child-buffer-limit`.

- `child-buffer-resume-threshold` `(integer, bytes, optional)`
  Logical queued-payload low-water mark for sending `FlowResume` after the local child becomes writable. The frame is
  sent once the sum of queued application payload bytes falls below this value, allowing the peer to restart before
  the queue is completely empty. It must be greater than `0`; its configured numeric value is capped to
  `child-buffer-limit`.

  Default: `262144` (`256 KiB`). Raising it resumes the peer earlier and may reduce high-RTT throughput gaps, at the
  cost of weaker hysteresis and potentially more pause/resume cycling.

  Both pause tolerance and resume threshold intentionally use logical payload bytes. Allocation charge is used only
  by the three memory-sensitive hard byte budgets.

- `parent-buffer-limit` `(integer, bytes, optional)`
  Per-parent retained-allocation-charge budget for child-destined queues across all children. When a newly queued
  buffer makes the total reach the budget, `MuxClient` closes the child with the largest retained charge. Equal-sized queues prefer the
  oldest attached child. This releases the pressure without pausing unrelated streams on the shared parent.

  Default: `33554432` (`32 MB`). Set to `0` to disable the aggregate budget; `child-buffer-limit` still bounds each
  individual child. The value may intentionally be lower than `child-buffer-limit`.

  The limit applies to each parent independently. Approximate worst-case live-queue charge is therefore
  `parent-buffer-limit` multiplied by the number of live parent lines (one per configured MuxClient pool slot).

- `detached-buffer-limit` `(integer, bytes, optional)`
  Per-worker retained-allocation-charge limit for child queues kept after their parent transport has closed. The default depends on
  the global `misc.ram-profile`, as shown below. Reaching the limit aborts only the newly detached blocked child. Set
  to `0` to disable this aggregate bound.

- `detached-child-limit` `(integer, optional)`
  Per-worker count limit for blocked children retained after parent loss. The default depends on the global
  `misc.ram-profile`, as shown below. Reaching the limit aborts only the newly detached blocked child. Set to `0` to
  disable this aggregate bound.

  | RAM profile | Default detached charge | Default detached children |
  | --- | ---: | ---: |
  | S1 (`minimal` / `ultralow`) | `33554432` (`32 MiB`) | `4096` |
  | S2 | `80740352` (`77 MiB`) | `5677` |
  | M1 (`client`) | `127926272` (`122 MiB`) | `7258` |
  | M2 (`client-larger`) | `174063616` (`166 MiB`) | `8838` |
  | L1 | `221249536` (`211 MiB`) | `10419` |
  | L2 (`server`, the global default) | `268435456` (`256 MiB`) | `12000` |

  Defaults are linearly interpolated over the six ordered RAM-profile tiers, with the charge limit rounded to the
  nearest whole MiB. An explicit setting overrides the profile-derived value independently for that limit.

- `log-main-line-stats` `(boolean, optional)`
  When `true`, each active parent transport line logs best-effort mux diagnostics every `5` seconds. Parent logical
  death suppresses normal stats execution; when the queued or timed runner is reached, the task settles as `LineDead`.
  Worker quiescence actively cancels pending queued or timed stats work. Neither path rearms it.

  The log keeps `parent-line-read-paused=no` for compatibility. Its `parent-queued-bytes` value is the same retained
  allocation charge enforced by `parent-buffer-limit`, not logical application payload bytes. It also reports
  `children-close-pending`, along with `wid`, parent-line write pause state, child count, child read-pause count, and
  child write-pause count.
  Default: `false`.

## Detailed Behavior

### Parent and child model

`MuxClient` keeps two kinds of lines:

- child lines: the logical streams coming from the previous node
- parent lines: the shared transport connections opened toward the next node

Each child line gets a 32-bit connection id (`cid`). That id is used inside MUX frames so the remote `MuxServer` can map traffic back to the correct child stream.

In timer and counter modes, `MuxClient` keeps one current reusable parent line per worker. The code calls this the unsatisfied line. As long as that parent is still allowed to accept more children, new child lines will join it. If another child arrives while the parent is at `max-children`, the parent is selection-retired, remains alive for current children, and closes at zero while the arriving child uses a new parent.

In fixed connection count mode, `MuxClient` keeps a fixed-size parent pool per worker. When a worker first needs a mux parent, it opens `per-worker-connections-count` parent transport lines for that worker. New child lines are assigned to the least-loaded non-finishing parent below `max-children`, with a round-robin tie break. If every fixed parent is full, the new borrowed child receives Finish immediately; no extra parent or unbounded wait queue is created. Capacity is reusable when a parent drops below the live cap.

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
- all modes: its concurrent live child count reaches `max-children`
- fixed connection count mode: age and cumulative counter do not retire parents, but the live cap still applies
- absolute hard limit: the parent connection id reaches `4294967295`

An exhausted parent line is not closed immediately. It simply stops accepting new child lines. Existing child streams continue using it until they finish.

When the parent is exhausted and its last child closes, `MuxClient` closes the parent transport line too. If a reusable
parent becomes exhausted while it has no active children, `MuxClient` closes it before replacing it with a new parent.

Child response lookup uses a per-parent hash index and remains average O(1). A
server resource-rejection `Close(cid)` finishes only that matching borrowed
child; the parent and unrelated siblings continue.

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
The peer has normally already received `FlowPause` for that `cid`; `child-buffer-pause-tolerance` is a backstop for a
child that paused before its `Open` frame was sent. Queued data is flushed when the child resumes. `FlowResume` is sent
once the child's queue drops below `child-buffer-resume-threshold`, allowing the peer to begin sending before the queue
is completely empty.

Queue pressure does not pause reads on the parent transport. A parent is shared by every child, so a parent read pause
taken for one indefinitely blocked destination also prevents unrelated child frames from being demultiplexed. That is
global head-of-line blocking even though the other streams and the parent transport are healthy.

Pressure is bounded by closing a child instead. If one child's retained queue charge reaches `child-buffer-limit`, that child is closed.
If the total retained charge reaches `parent-buffer-limit`, the child retaining the largest charged allocation is closed; equal-size ties prefer
the oldest attached child. The total was below the budget before the newest buffer, and the largest queue charge is
at least that buffer's charge, so one close returns the parent below budget in the normal accounting path.

Logical queue length remains the sum of application payload bytes and continues to drive `FlowPause`/`FlowResume`.
Zero-length `Data` is valid wire input: it adds no logical payload activity, but a retained zero-length frame has a
positive allocation charge and therefore advances every applicable hard memory budget.

The charge approximates memory retained by live Mux queues, not whole-process RSS. Allocator caches, queue-ring
storage, and the buffer pools' fixed baseline may remain allocated outside a particular live queue's charge.

When the remote side pauses the shared parent line, `MuxClient` tries to pause the child that most recently wrote to that parent. If no recent writer is known, it pauses all attached children. Resume only clears parent-write pressure; a child that is still under peer `FlowPause` remains paused.

A peer `Close` is ordered after earlier `Data` for the same `cid`. If the local child destination is paused,
`MuxClient` retains those earlier bytes and waits for Resume; it never forces Payload through Pause and sends local
Finish only after the queue is empty and writable. Later frames for that closed `cid` are discarded while unrelated
children on the parent continue normally.

During normal operation, if the parent transport is lost, the parent line still closes immediately. Already accepted child-destined queues
become child-only detached drains: writable children complete immediately, while paused children continue on later
Resume without retaining or dereferencing the dead parent. New outbound child data is rejected in this state.
`detached-buffer-limit` bounds the aggregate retained allocation charge and `detached-child-limit` bounds the retained
child count per worker. `MuxClient` borrows
child lines, so their true source owners remain responsible for enumerating and finishing them during shutdown.

### Buffering and overflow handling

Replies from the parent transport are accumulated in a read stream until complete MUX frames are available.

Current overflow limit:

- `1 MB` buffered on the parent read stream

If that limit is exceeded, `MuxClient` discards the incomplete parent remainder, closes the parent line, and applies
the same detached drain behavior to already parsed child queues.

## Notes And Caveats

- `MuxClient` is intended to be paired with `MuxServer`.
- `mode` is mandatory in the current implementation.
- `connection-duration-ms` is only valid in timer mode.
- `connection-capacity` is only valid in counter mode.
- `per-worker-connections-count` is only valid in fixed connection count mode.
- A local child Finish or orderly process shutdown may release a residual detached queue instead of forwarding it.
- The detached drain changes no MUX wire bytes or peer capability requirements.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation, so this node is not meant to be used as a generic chain endpoint.

## Worker shutdown

During worker quiescence, `MuxClient` switches terminal cleanup to discard retained MUX queues without sending
payload, Open/Close frames, or flow-control work. Each worker inventories every parent it creates independently
of selection, including connecting, idle, active, and retired parents. Worker stop closes that inventory and
finishes attached children toward their source owners, which destroy the borrowed child lines. Previously detached
borrowed children may outlive the MUX worker hook; their state and exact queue accounting remain available until
their source owners send Finish. Final instance destruction requires both ownership and detached accounting to be
empty. Ordinary connection loss and ordered peer Close retain their normal backpressure-driven drain behavior.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `16` bytes |
