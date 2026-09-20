<!--
Documentation version: 161
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

### Parent write buffering

Each parent has a lazy FIFO of encoded outgoing buffers, shared by its children.
The following optional settings measure **queue-capacity charge in bytes**:
`sizeof(sbuf_t) + sbufGetTotalCapacity(buf) + kSbufAllocationAlignment`.
Ordinary capacity is resident allocation; splice capacity is logical geometry.
Padding is included once. Kernel pipe capacity and control storage are not added;
this is not a physical memory, descriptor, or RSS limit.

| Setting | Default | Meaning |
| --- | --- | --- |
| `parent-write-buffer-pause-threshold` | `16777216` (16 MiB) | Pause attached child producers when retained charge reaches this value. |
| `parent-write-buffer-resume-threshold` | `12582912` (12 MiB) | Release parent pressure at or below this charge while transport is writable. Omitted values derive from pause × 3/4, rounded down. |
| `parent-write-buffer-limit` | `134217728` (128 MiB) | Maximum retained charge for each parent; equality is allowed. |

Pause and hard limits must be integers in `[1, INT_MAX]`; resume accepts
`[0, INT_MAX]`. The effective tuple must satisfy `0 <= resume < pause < hard`.
Omitted pause and hard settings use their defaults; omitted resume derives as
`floor(pause * 3 / 4)` with a wide intermediate. Explicit zero requests
empty-queue release, still subject to transport writability. Booleans, strings,
null, fractions, negatives and out-of-range values reject startup. Invalid
combinations report all three effective values without clamping. For example,
inside `settings` (derives a 1.75 MiB resume threshold):

```json
{
  "parent-write-buffer-pause-threshold": 2097152,
  "parent-write-buffer-limit": 4194304
}
```

The gate uses retained queue charge (`sbufGetQueueCharge`), including header,
capacity, padding and alignment, rather than wire length. Resume runs before the
next FIFO pop, after the prior delivery returns. Synchronous resumed output
appends behind existing frames and complete splice batches. A new pause stops
an interrupted Resume pass; a parent-local rotating cursor gives later eligible
children their next opportunity. Init/Est completion reconciles the current gate.
Peer FlowPause and terminal close remain independent reasons to stop a source.

The 4 MiB hysteresis gap avoids waiting for the entire queue to drain, but does
not promise continuous sender throughput or a faster carrier. The 128 MiB limit
is per parent, allocated on demand, and is not an RSS, socket-buffer or FD bound.
Already-admitted Data can still reach a peer-paused child; the default 24 MiB
child and 128 MiB parent receive budgets can shed children or close that parent.

With `log-main-line-stats`, five-second samples include
`parent-output-queued-bytes`, `parent-output-queue-charge`,
`parent-output-queue-items`, `parent-transport-paused`,
`parent-sources-throttled`, `children-parent-write-paused`,
`children-peer-flow-paused`, `parent-output-throttle-ms`, and
`parent-output-last-throttle-ms`, plus the three effective settings.
Throttle durations use the owner's 64-bit monotonic clock; current duration is
zero outside a throttle episode. `parent-child-queue-charge` and
`parent-input-queue-charge` describe incoming storage. Logging remains optional
and has no role in flow-control progress.

These settings apply independently to every parent of this node. They are separate
from `parent-buffer-limit`, which bounds incoming assembly plus attached child queues.

## Optional `settings` Fields

- `max-children` `(integer, optional)`
  Maximum concurrent live children on one parent. Default: `10000`. It must be
  positive and is separate from counter mode's cumulative
  `connection-capacity`.

- `child-buffer-limit` `(integer, bytes, optional)`
  Maximum queue-capacity charge per paused child line before `MuxClient` closes that child stream.
  Ordinary entries charge actual capacity (including padding), the buffer header, and alignment overhead.
  Splice entries charge logical sbuf capacity plus sbuf/alignment overhead, including reserved padding once.

  Default: `25165824` (`24 MiB`).

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

  Both pause tolerance and resume threshold intentionally use logical payload bytes. Queue-capacity charge is used by the hard retention budgets.

- `parent-buffer-limit` `(integer, bytes, optional)`
  Per-parent queue-capacity budget for incoming assembly plus all attached child queues.
  On reaching it, beneficial incoming compaction precedes largest-child shedding; ties prefer the oldest child.
  Recovery may close several children or, if pressure cannot be relieved, the affected parent.

  Default: `134217728` (`128 MiB`). Set to `0` to disable the aggregate budget; `child-buffer-limit` still bounds each
  individual child. The value may intentionally be lower than `child-buffer-limit`.

  Each parent has an independent retained-state limit, with transient delivered input excluded from an instantaneous ceiling.

- `detached-buffer-limit` `(integer, bytes, optional)`
  Per-worker queue-capacity-charge limit for child queues kept after their parent transport has closed. The default depends on
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

  The log keeps `parent-line-read-paused=no` for compatibility. Its `parent-child-queue-charge` and
  `parent-input-queue-charge` fields report the separate charges whose sum is limited by
  `parent-buffer-limit`, not logical payload bytes. It also reports
  `children-close-pending`, along with `wid`, parent-line write pause state, child count, child read-pause count, and
  child write-pause count.
  Default: `false`.

## Detailed Behavior

### Parent and child model

`MuxClient` keeps two kinds of lines:

- child lines: the logical streams coming from the previous node
- parent lines: the shared transport connections opened toward the next node

Each child line gets a 32-bit connection id (`cid`). That id is used inside MUX frames so the remote `MuxServer` can map traffic back to the correct child stream.

In timer and counter modes, `MuxClient` keeps one current reusable parent line per worker. The code calls this the unsatisfied line. As long as that parent is still allowed to accept more children, new child lines will join it. If another child arrives while the parent is at `max-children`, the parent is selection-retired, remains alive for current children, and closes after the last child leaves and pending output is handed off; the arriving child uses a new parent.

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

When an exhausted parent has no children, `MuxClient` retires it from selection and
closes it once pending encoded output has been handed off and no send is active.
A replacement parent can serve new children while the old parent waits for Resume.
The owned-parent inventory retains the old parent throughout that wait.

Child response lookup uses a per-parent hash index and remains average O(1). A
server resource-rejection `Close(cid)` finishes only that matching borrowed
child; the parent and unrelated siblings continue.

### Internal frame format

`MuxClient` and `MuxServer` share the same fixed header format:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 3 bytes | Unsigned payload length, big-endian. |
| 3 | 1 byte | Frame type/flags. |
| 4 | 4 bytes | Unsigned connection ID, big-endian. |

The inclusive payload maximum is **1 MiB (1,048,576 bytes)** for every frame
type, independent of RAM profile, buffer sizes and requested or granted pipe
capacity. A maximum frame occupies 1,048,584 wire bytes; a preceding Open adds
another eight bytes (1,048,592 total). Decoding rejects a larger declaration as
soon as all eight header bytes arrive, even for unknown CIDs or types, and closes
only that parent through normal parent-loss cleanup. Permitted frames wait for
the complete body; unknown frames consume their declared body and empty Data
still produces one delivery. Complete frames drain before the incomplete
remainder is checked against **1,048,584 bytes**, including its cached header.

Header size: `8 bytes`

Frame flags:

- `0`: `Open`
- `1`: `Close`
- `2`: `FlowPause`
- `3`: `FlowResume`
- `4`: `Data`

Payload length is the framed data length after the header.

`1,048,576` bytes is the maximum payload of one `Data` frame, not a limit on one
child `Payload` callback. The encoder splits a larger callback payload into
consecutive `Data` frames of at most `1,048,576` bytes and preserves the exact byte
order. The checked aggregate encoded size (payload plus every 8-byte frame
header and an optional `Open` frame) must fit in `uint32_t`. If it does not, the
ordinary input buffer is recycled and only that child is closed; no partial frame
is published. Large splice batches instead use affected-parent refusal and their
complete-batch resource limit, described below. Allocation of the checked aggregate buffer follows the shift-buffer
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
When incoming assembly plus attached child charge reaches `parent-buffer-limit`, beneficial incoming
compaction runs first. Remaining pressure closes the largest queued child with the oldest tie-break,
rechecking after each callback. Multiple closes may be needed; unrelieved pressure closes the parent.

Logical queue length remains the sum of application payload bytes and continues to drive `FlowPause`/`FlowResume`.
Zero-length `Data` is valid wire input: it adds no logical payload activity, but a retained zero-length frame has a
positive allocation charge and therefore advances every applicable hard queue budget.

The queue-capacity charge is a policy budget, not exact kernel memory or whole-process RSS. Allocator caches, queue-ring
storage, and the buffer pools' fixed baseline may remain allocated outside a particular live queue's charge.

Parent transport `Pause` immediately stops every parent-bound Payload callback,
including controls and Close replies. New encoded output joins the parent's FIFO;
it does not depend on the originating child remaining alive. Short stalls below
`parent-write-buffer-pause-threshold` cause no child-wide callback pass. Reaching
the threshold pauses attached child producers once; newly initialized children
inherit that gate after their producer Init/Est callback returns.

`Resume` drains FIFO order until empty or paused again. Queue-throttled producers
resume at or below `parent-write-buffer-resume-threshold` while the transport is writable; peer FlowPause
and terminal-close pressure remain independent. Reentrant output joins the FIFO
behind older output. Incoming parent reads and unrelated parents remain active.

A candidate that would exceed `parent-write-buffer-limit`, or a queue reservation
failure, closes only the affected parent through normal local teardown. The
candidate and undeliverable output are recycled; the process is not terminated.
An unblocked direct write needs no FIFO allocation and is not constrained by the
retention limit. Small control frames use a fitting small pooled allocation with
chain padding. Parent loss immediately discards outgoing backlog, while existing
incoming child queues retain their separate detached-drain behavior.

An exhausted timer/counter parent with no remaining children stays in MuxClient's
owned-parent inventory until its queued final frames have been handed off and no
send is active. It is retired from new-child selection while waiting. Fixed
parents remain reusable under their existing policy. Worker Stop discards pending
output and closes all owned parents, including retired parents with no children.

A peer `Close` is ordered after earlier `Data` for the same `cid`. If the local child destination is paused,
`MuxClient` retains those earlier bytes and waits for Resume; it never forces Payload through Pause and sends local
Finish only after the queue is empty and writable. Later frames for that closed `cid` are discarded while unrelated
children on the parent continue normally.

During normal operation, if the parent transport is lost, the parent line still closes immediately. Already accepted child-destined queues
become child-only detached drains: writable children complete immediately, while paused children continue on later
Resume without retaining or dereferencing the dead parent. New outbound child data is rejected in this state.
`detached-buffer-limit` bounds the aggregate queue-capacity charge and `detached-child-limit` bounds the retained
child count per worker. `MuxClient` borrows
child lines, so their true source owners remain responsible for enumerating and finishing them during shutdown.

### Buffering and overflow handling

Replies from the parent transport are accumulated in a read stream until complete MUX frames are available.

Current overflow limit:

- `1,048,584 bytes` of incomplete parent input, including the eight-byte header

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

## Frame boundaries and UDP

The parent receive accumulator uses a dedicated fixed-header splice stream.
It physically caches only the eight-byte header and extracts exactly the declared
body after it is complete. Bodies may split one source pipe or combine several
pipes while preserving FIFO order and independent ownership. The next header is
cached only after the current body is consumed. Child callbacks receive only the
body; paused-child queues preserve one entry and callback per Data frame.

Zero-length child payloads are valid: the encoder emits a `Data` frame with an
eight-byte header and no body. The decoder delivers an empty payload; this is
neither EOF nor `Close`. Empty frames remain separate through paused-child
queues even when their total logical byte count is zero. They still incur the
existing queue-capacity charge and do not count as nonempty idle activity.

MUX preserves its wire-frame boundaries, not every original callback or UDP
datagram boundary. Both encoders put a payload of at most `1,048,576` bytes in one
`Data` frame and split larger payloads into several frames. The receiver does
not reassemble the original callback boundary. A transform on the child side
can also change payload boundaries before framing or after decoding.

For UDP traffic, use explicit `UdpOverTcpClient`/`UdpOverTcpServer` framing
around the byte-stream portion of the chain rather than relying on an unusual
direct UDP/MUX arrangement:

```text
client: UdpListener -> UdpOverTcpClient -> MuxClient -> TcpConnector
server: TcpListener -> MuxServer -> UdpOverTcpServer -> UdpConnector
```

Direct UDP adapters next to MUX can retain datagrams that arrive intact and fit
one `Data` frame, but this is not general boundary protection across arbitrary
chains. The UDP framing pair has its own limits: currently it requires nonempty
datagrams. Its restriction does not change MUX's support for empty `Data`.

### Splice retention and large batches

See the developer guide for the [limits table](https://radkesvat.github.io/WaterWall-Docs/docs/devguides/part3-buffers-and-padding#queue-capacity-budgets),
[allocation and data-flow walkthrough](https://radkesvat.github.io/WaterWall-Docs/docs/devguides/part3-buffers-and-padding#mux-allocation-and-data-flow),
and [edge-case reference](https://radkesvat.github.io/WaterWall-Docs/docs/devguides/part3-buffers-and-padding#mux-buffer-edge-cases).

Mux uses one **queue-capacity charge** for every owned buffer:

```text
sizeof(sbuf_t) + sbufGetTotalCapacity(buf) + kSbufAllocationAlignment
```

Capacity includes reserved left padding. Ordinary entries therefore retain their
allocation-based charge; splice entries charge logical sbuf capacity, without
adding wrapper control storage or kernel pipe capacity. Unknown cached pipe
capacity does not force a valid retained source into ordinary storage.

`parent-buffer-limit` (128 MiB by default) covers incoming frame assembly plus
all attached child queues. The stream counter remains separate from the child
aggregate, and their sum is checked at stable return boundaries. Complete frames
in a coalesced delivery drain first, even if its temporary charge exceeds the
limit. Cached header bytes count toward the independent 1,048,584-byte incomplete
frame bound, but the header cache and stream/queue metadata carry no sbuf charge.
Active splice-head body consumption reduces logical capacity and its charge;
prefix consumption and ordinary cursor movement do not reduce capacity.

Reaching a finite receive limit first attempts to combine incoming fragments
into one ordinary best-fit buffer, only if its predicted total charge is strictly
lower. Compaction preserves the cached header and exact byte order. It does not
run on every Push or rewrite child/output queues. Remaining pressure sheds the
largest queued child, preferring the oldest on ties, and rechecks after every
callback. Several victims may be needed. No victim or no progress closes only
that parent through normal parent-loss cleanup. A zero parent limit disables
this combined finite bound; it introduces no other aggregate cap.

`child-buffer-limit` remains 24 MiB by default and rejects equality. Outgoing
parent queues remain separate: their pause/resume thresholds are 16/12 MiB, hard limit is
128 MiB, and hard-limit equality is permitted. Detached queues retain their
per-worker settings and zero/unlimited meanings. FlowPause/FlowResume continue
to count logical payload bytes. Ordinary child candidates may still compact to
a cheaper pooled tier; valid splice candidates are not individually materialized
for queue pressure.

There is no worker-wide pipe-count or pipe-capacity quota. Other parents cannot
force fallback through shared pipe reservations. These charges are not physical
memory, FD, kernel page-reference, socket-queue or RSS bounds, nor a strict
instantaneous memory ceiling. More retained splice data can use more descriptors
and nominal kernel capacity under the same logical budget. Pools may cache empty
pipes after recycling; lower charge does not prove those resources were closed.

Inputs through 1 MiB use the fitting single-buffer path, including one Data header
for empty input. Larger ordinary input uses one encoded aggregate; larger splice
input uses a complete ordered batch, with Open once before the first client Data.
A real 1 MiB pipe body plus a resident prefix can require splitting. Batch staging
uses completed logical capacity for pipe estimates and reserves ordinary fallback
costs for the remaining frames. All fallible admission precedes publication and
callbacks. Refusal discards the local batch and closes only the affected parent.
A fitting writable-parent direct write still needs no FIFO admission.

Actual pipe creation, capacity and slot pressure remain transfer constraints.
Short progress/EINTR and complete ordinary fallback preserve every byte, even
after partial transfer. Nominal 1 MiB capacity does not prove available slots.
Best-fit fallback preserves headroom and may exceed a low-profile large tier.
Pool sizes, pipe targets, protocol limits and JSON defaults remain unchanged.

Pause stops the output pump; Resume preserves FIFO. Nested output and child Close
follow admitted Data. Child death does not release parent-owned output. Parent
loss discards incoming/output ownership and transfers eligible blocked child
queues to detached accounting. Pop, transfer and discard settle scalar charges
before callbacks; final owner cleanup settles every queue. HTTP and ordinary
BufferStream remain ordinary-only.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `16` bytes |
