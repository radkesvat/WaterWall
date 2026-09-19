<!--
Documentation version: 161
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/MuxServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/MuxServer.mdx, and all files must keep the same documentation version.
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

### Parent write buffering

Each parent has a lazy FIFO of encoded outgoing buffers, shared by its children.
The following optional settings measure **queue-capacity charge in bytes**:
`sizeof(sbuf_t) + sbufGetTotalCapacity(buf) + kSbufAllocationAlignment`.
Ordinary capacity is resident allocation; splice capacity is logical geometry.
Padding is included once. Kernel pipe capacity and control storage are not added;
this is not a physical memory, descriptor, or RSS limit.

| Setting | Default | Meaning |
| --- | --- | --- |
| `parent-write-buffer-pause-threshold` | `8388608` (8 MiB) | Pause attached child producers when retained charge reaches this value. |
| `parent-write-buffer-limit` | `16777216` (16 MiB) | Maximum retained charge for each parent; equality is allowed. |

Both must be integers in `[1, INT_MAX]`, with the pause threshold strictly below
the hard limit. Zero, negative, fractional, nonnumeric, and out-of-range values
reject startup. Each omitted field independently uses its default; the final
pair is validated without adjusting either value. A hard limit below 8 MiB
therefore requires overriding the pause threshold too. For example, inside
`settings`:

```json
{
  "parent-write-buffer-pause-threshold": 2097152,
  "parent-write-buffer-limit": 4194304
}
```

These settings apply independently to every parent of this node. They are separate
from `parent-buffer-limit`, which bounds incoming assembly plus attached child queues.

## Optional `settings` Fields

- `child-buffer-limit` `(integer, bytes, optional)`
  Maximum queue-capacity charge per paused child line before `MuxServer` closes that child stream.
  Ordinary entries charge actual capacity (including padding), the buffer header, and alignment overhead.
  Splice entries charge logical sbuf capacity plus sbuf/alignment overhead, including reserved padding once.

  Default: `25165824` (`24 MB`).

- `child-buffer-pause-tolerance` `(integer, bytes, optional)`
  Logical queued-payload backstop for sending a `FlowPause` frame for a paused child.

  `FlowPause` is normally sent as soon as the child's local write side pauses, before data is queued. This threshold
  covers any ordering edge where the peer has not yet been told to stop. Raising it does not normally delay peer
  throttling.

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

  Default: `50331648` (`48 MiB`). Set to `0` to disable the aggregate budget; `child-buffer-limit` still bounds each
  individual child. The value may intentionally be lower than `child-buffer-limit`.

  Each parent has an independent retained-state limit, with transient delivered input excluded from an instantaneous ceiling.

- `max-children` `(integer, optional)`
  Hard maximum attached live children on one parent transport. Default: `10000`.
  It must be positive and no greater than `max-live-children`.

- `max-live-children` `(integer, optional)`
  Hard maximum reserved or initialized children across this MuxServer instance,
  all parents, and all workers. Default: `262144`. Draining and detached children
  remain counted until their MuxServer line state is destroyed.

- `initial-child-idle-timeout-ms` / `active-child-idle-timeout-ms` `(integer, milliseconds, optional)`
  Two-phase child idle timeouts. Defaults: `10000` and `300000`. Both must be
  positive, and the active timeout must be at least the initial timeout.

- `memory-high-watermark-percent` / `memory-low-watermark-percent` `(integer, optional)`
  Memory admission hysteresis. Defaults: `85` and `75`. Both must be in
  `[1, 99]`, and low must be strictly below high.

- `memory-reserve` `(integer, bytes, optional)`
  Also stops new Opens when effective available memory reaches this reserve.
  The default follows the RAM-profile byte table below. It must be in
  `[0, INT_MAX]`; zero disables only the absolute reserve.

- `memory-fallback-max-live-children` `(integer, optional)`
  Aggregate ceiling used while the cached memory snapshot is unavailable,
  unsupported, or older than one second. The default follows the RAM-profile
  child table below. It must be positive and no greater than `max-live-children`.

- `detached-buffer-limit` `(integer, bytes, optional)`
  Per-worker queue-capacity-charge limit for blocked child queues kept after parent loss. The default depends on the global
  `misc.ram-profile`, as shown below. Reaching it aborts only the newly detached blocked child. Set to `0` to disable
  this aggregate bound.

- `detached-child-limit` `(integer, optional)`
  Per-worker count limit for blocked children retained after parent loss. The default depends on the global
  `misc.ram-profile`, as shown below. Reaching it aborts only the newly detached blocked child. Set to `0` to disable
  this aggregate bound.

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

  The memory admission reserve and fallback ceiling initially use the same six
  byte/child values, through an independent admission-default policy.

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

`MuxServer` works with two kinds of lines:

- the parent line: the shared transport line that carries MUX frames from the previous node
- child lines: logical streams created by `MuxServer` when it receives `Open` frames

Each child line is keyed by the `cid` carried in the frame header.

When an `Open` frame arrives:

- `MuxServer` performs average-O(1) duplicate lookup and applies the parent,
  instance, and cached-memory admission gates
- an admitted Open reserves capacity and creates a child line on the same worker
- initializes line state for that child
- links it to the parent line
- calls upstream `init` on the next node for that child line

After that, `Data`, `Pause`, `Resume`, and `Close` frames for the same `cid` are routed to that child.

A resource-rejected fresh Open allocates no child, sends `Close(cid)`, and keeps
the healthy parent and siblings alive. A duplicate Open is a protocol violation
and closes the parent. Rejected-Open abuse is bounded by a 1024-token burst
bucket refilled at 64 tokens per second; sustained excess closes that parent.

Fresh memory data is published by the process-global sampler every `500` ms and
expires after one second. On Linux, cgroup pressure is the maximum used
percentage and the minimum remaining allowance across every visible finite
cgroup v2/v1 level; `MemAvailable` still bounds effective headroom. Ambiguous or
hidden cgroup constraints use the conservative fallback. Windows uses available
physical memory. Workers consume only the cached atomic tuple. Stale or
unsupported data uses the profile fallback ceiling and never reopens a
pressure-closed gate.

### Child idle lifetime

Open-only children expire after `initial-child-idle-timeout-ms`. The first
nonempty incoming or outgoing payload switches to the active timeout, and each
later nonempty payload refreshes it. Control frames, Init/Est, and zero-length
Data do not refresh it. Expiry sends `Close(cid)` when possible, closes only the
owned child, and preserves the parent and siblings. Explicit close immediately
removes the timer item.

Limits count concurrent live state rather than historical CIDs, so destroyed
children free capacity and parent transports remain reusable for their full
transport lifetime. There is no MUX wire-format change.

### Internal frame format

`MuxServer` expects the same 8-byte header used by `MuxClient`:

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

One MUX `Data` frame carries at most `1,048,576` payload bytes. The shared encoder
splits a larger downstream child payload into consecutive `Data` frames in byte
order. The complete encoding, including all headers, must fit in `uint32_t`;
an unrepresentable encoding recycles the input and closes only that child.
The receiver does not restore the original callback boundary after this split.

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

During normal operation, if a child finishes from the service-facing side, `MuxServer` sends a `Close` frame back on the parent line.

During normal operation, if the parent transport line itself finishes, its borrowed MUX state is destroyed immediately. Already accepted child
queues detach from it and drain independently under ordinary child Pause/Resume. `MuxServer` inventories these owned
detached children per worker, rejects new outbound child data, and finishes/destroys each child after its queue drains.
`detached-buffer-limit` bounds queue-capacity charge and `detached-child-limit` bounds child count per worker.

### Pause and resume behavior

Per-child `FlowPause` and `FlowResume` frames are forwarded to the matching child line.

If writing parent-delivered data to a child causes that child to pause, `MuxServer` queues later data for that child.
`FlowPause` is sent as soon as the local child write side pauses, before later data is queued for it. Queued data is
flushed when the child resumes. `FlowResume` is sent once the child's queue drops below
`child-buffer-resume-threshold`, allowing the peer to begin sending before the queue is completely empty.

Queue pressure does not pause reads on the parent transport. A parent is shared by every child, so a parent read pause
taken for one indefinitely blocked destination also prevents unrelated child frames from being demultiplexed. That is
global head-of-line blocking even though the other streams and the parent transport are healthy.

Pressure is bounded by closing a child instead. If one child's retained queue charge reaches `child-buffer-limit`, that child is closed.
When incoming assembly plus attached child charge reaches `parent-buffer-limit`, beneficial incoming
compaction runs first. Remaining pressure closes the largest queued child with the oldest tie-break,
rechecking after each callback. Multiple closes may be needed; unrelieved pressure closes the parent.

Logical queue length remains the sum of application payload bytes and continues to drive `FlowPause`/`FlowResume`.
Zero-length `Data` remains non-activity for child idle timing. If it must be retained for a paused child, however, it
has a positive allocation charge and advances every applicable hard queue budget.

The queue-capacity charge is a policy budget, not exact kernel memory or whole-process RSS. Allocator caches, queue-ring
storage, and the buffer pools' fixed baseline may remain allocated outside a particular live queue's charge.

Parent transport `Pause` immediately stops every parent-bound Payload callback,
including controls and Close replies. New encoded output joins the parent's FIFO;
it does not depend on the originating child remaining alive. Short stalls below
`parent-write-buffer-pause-threshold` cause no child-wide callback pass. Reaching
the threshold pauses attached child producers once; newly initialized children
inherit that gate after their producer Init/Est callback returns.

`Resume` drains FIFO order until empty or paused again. Queue-throttled producers
resume only when the FIFO is empty and the transport is writable; peer FlowPause
and terminal-close pressure remain independent. Reentrant output joins the FIFO
behind older output. Incoming parent reads and unrelated parents remain active.

A candidate that would exceed `parent-write-buffer-limit`, or a queue reservation
failure, closes only the affected parent through normal local teardown. The
candidate and undeliverable output are recycled; the process is not terminated.
An unblocked direct write needs no FIFO allocation and is not constrained by the
retention limit. Small control frames use a fitting small pooled allocation with
chain padding. Parent loss immediately discards outgoing backlog, while existing
incoming child queues retain their separate detached-drain behavior.

MuxServer borrows its parent lines: local overflow destroys its parent state and
notifies the parent owner, while MuxServer itself closes its owned children.
Rejected-Open Close replies use the same FIFO as Data and other controls.

### Buffering and overflow handling

Incoming MUX bytes are buffered until a full frame is available.

Current overflow limit:

- `1,048,584 bytes` of incomplete parent input, including the eight-byte header

If that limit is exceeded, `MuxServer` discards the incomplete parent remainder, finishes the parent line toward the
previous side, and applies the same detached drain behavior to already parsed child queues.

## Notes And Caveats

- `MuxServer` is intended to be paired with `MuxClient`.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.
- A duplicate `Open` for an already indexed `cid` is a protocol violation that closes the parent.
- A service-side Finish or orderly worker shutdown may discard residual detached data. Worker shutdown forwards no
  queued Payload, even for a writable child, before closing every remaining owned child.
- The detached drain changes no MUX wire bytes or peer capability requirements.

## Worker shutdown

During worker quiescence, `MuxServer` detaches its idle timer and switches terminal cleanup to discard retained
MUX queues without sending payload, Close frames, or flow-control work. Its worker-local child idle table
inventories every owned child, attached or detached. Worker stop drains the complete table, releases each child’s
queue charge and live reservation exactly once, finishes toward the child destination, and destroys the child.
A borrowed parent can remain alive with valid MUX state and outgoing backlog until its actual owner sends Finish later. The idle
table is destroyed on its worker after drain; aggregate live-child checks run after all workers have stopped.
Ordinary connection loss, idle expiry, and ordered peer Close keep their normal runtime behavior.

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

`parent-buffer-limit` (48 MiB by default) covers incoming frame assembly plus
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
parent queues remain separate: their pause threshold is 8 MiB, hard limit is
16 MiB, and hard-limit equality is permitted. Detached queues retain their
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
| `required_padding_left` | `8` bytes |
