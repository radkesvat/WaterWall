<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/HalfDuplexServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/HalfDuplexServer.mdx, and all files must keep the same documentation version.
-->

# HalfDuplexServer Node

`HalfDuplexServer` is the server-side peer of `HalfDuplexClient`. It receives two separate inbound half-connections, matches them by an internal identifier, and reconstructs one normal logical line toward the next node.

In practice, this node is used together with `HalfDuplexClient` on the other side of the transport.

## What It Does

- Accepts inbound half-connections from the previous node.
- Reads an internal 17-byte intro containing an exact role and a 128-bit pair ID.
- Matches upload and download connections that belong together.
- Creates one normal main line toward the next node after both halves are available.
- Forwards upload-side payload to the next node.
- Sends downstream replies from the next node back through the download-side connection.

This tunnel effectively turns two transport connections into one logical connection for the service-facing side.

## Typical Placement

A common layout is:

- transport-facing node before `HalfDuplexServer`
- `HalfDuplexServer`
- normal stream-oriented service nodes after it

`HalfDuplexServer` should usually sit opposite `HalfDuplexClient`.

## Configuration Example

```json
{
  "name": "halfduplex-server",
  "type": "HalfDuplexServer",
  "settings": {},
  "next": "service-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"HalfDuplexServer"`.

- `next` `(string)`
  The next node that should receive the reconstructed logical line.

### `settings`

There are no required tunnel-specific settings in the current implementation.

## Optional `settings` Fields

There are no tunnel-specific optional settings in the current implementation.

## Detailed Behavior

### Upload and download matching

Each incoming transport line begins in an unknown state.

`HalfDuplexServer` waits until it has the complete 17-byte intro, then reads the exact role byte and full 128-bit identifier sent by `HalfDuplexClient`.

From that block it extracts:

- the logical connection's full 128-bit pair ID
- whether this line is the upload side or the download side

It then uses two hash maps:

- upload-line map
- download-line map

If the matching peer half is already waiting, the server pairs them immediately.

If not, the half-connection is stored in the appropriate map until its partner arrives.

### Main line creation

Once both halves are available:

- `HalfDuplexServer` creates one main line toward the next node
- links that main line to the upload and download transport lines
- initializes the next node with that main line

After this point, the next node sees a normal single logical line and does not need to know that it came from two transport connections.

### Data flow direction

- Upload half to main line: previous node -> upload line -> `HalfDuplexServer` -> next node
- Main line reply to download half: next node -> `HalfDuplexServer` -> download line -> previous node

The upload line is where client-originated payload enters.

The download line is where service replies are written back.

### Handling of the first payload

The first upload-side payload includes both:

- the 17-byte intro
- the user's first real payload after that intro

When pairing succeeds, `HalfDuplexServer` strips the intro bytes and forwards any remaining upload payload to the newly created main line.
The pair ID is internal routing metadata. It does not authenticate either half
or protect the transport; configure security nodes when those properties are
required.

The download-side intro carries no user payload. It is consumed only for matching.

### Worker handoff behavior

This tunnel is created through the pipe-tunnel wrapper so it can move a half-connection to the worker that already owns its matching partner.

If the upload and download halves arrive on different workers:

- the later line is piped to the worker that owns the earlier half
- pairing then continues on that worker

This is an important implementation detail because the two halves may not land on the same worker naturally.

### Temporary buffering

If an upload half arrives before its matching download half, the server buffers its payload until the pair is complete.

Current maximum buffered size for a waiting upload half:

- `131070 * max(1, ceil(L / 32768))` bytes, with `L` from the line pool's independent waiting-budget basis (64 KiB in S1/S2, 1 MiB in higher profiles)

If that limit is reached before the matching download half appears, the waiting upload line is closed.

Download halves are not buffered the same way. They are mainly stored as waiting entries until the upload side arrives.

### Pause and resume behavior

If the download transport line is paused or resumed by the previous side, `HalfDuplexServer` forwards that pause or resume to the main line toward the next node.

If the next side pauses or resumes the main line, `HalfDuplexServer` forwards that control to the upload transport line.

This matches the direction of traffic pressure:

- backpressure on downstream replies affects the main line
- backpressure from the service side affects the upload path

### Finish behavior

If either half-connection closes after pairing:

- the main line is finished and destroyed
- the other half-connection is scheduled to close

If a half-connection closes before pairing completes, it is removed from the waiting map and cleaned up.

If the next side closes the reconstructed main line, `HalfDuplexServer` finishes the download line immediately and schedules the upload line to close.

## Notes And Caveats

- `HalfDuplexServer` is intended to be paired with `HalfDuplexClient`.
- There are no tunnel-specific JSON settings today.
- The tunnel depends on an internal 17-byte intro shared with `HalfDuplexClient`.
- Waiting upload halves can buffer data, but waiting download halves are mostly just registered in the map.
- The current implementation uses a pipe-tunnel wrapper internally for cross-worker pairing.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.

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
| `required_padding_left` | `0` bytes |

The waiting bound applies at initial publication and on later appends. Close occurs at or above 262,140 bytes in S1/S2 or 4,194,240 bytes in higher profiles; available peers pair before waiting limits apply.

## Splice and setup storage

Any delivery used to parse an intro or extend a waiting upload is materialized
completely, including body bytes accompanying the intro. Retained setup buffers
are ordinary. Pairing strips exactly 17 bytes and replays the retained body before
later direct traffic. After startup replay completes, upload and return traffic preserve ordinary
or splice wrappers, including across workers. Download-side input after its intro
is discarded without materializing its body.

The waiting-upload limit remains `131070 * max(1, ceil(basis / 32768))`, including
the retained intro: close at or above 262,140 bytes in S1/S2 or 4,194,240 bytes in
higher profiles. An available peer pairs before this waiting-limit check. These
are logical waiting limits, not a cap on ready deliveries or total physical memory.
Fresh materialization and grown waiting buffers retain onward padding.

Both nodes advertise `kNodeFlagSupportsSplice` with zero required left padding.
Actual splice reads require platform/build support, `misc.splice` enabled, and
support from every node in the expanded chain, including the server's PipeTunnel
wrapper and all neighbors. Ordinary buffers remain valid in every state. No new
settings, wire fields, or read-preference requests are introduced.

### Ordering during main-line startup

Pairing publishes a temporary startup barrier before invoking next Init. The
server-owned main line owns the initial ordinary body separately from later
upload input. Input received reentrantly during Init or initial replay cannot
overtake that body. An empty initial body still preserves the Init barrier.

Later input retained by this barrier has independent inclusive limits of 2 MiB
logical bytes, 2 MiB canonical allocation charge, and 1,024 entries. Empty entries
consume charge and an entry; allocation capacity may exhaust the charge limit
before the byte limit. Refusal closes the association rather than dropping TCP
bytes. The initial body is outside this new budget: its existing admission and
waiting-upload limits remain unchanged, including immediately pairable large
inputs.

All startup retention is ordinary. Splice deliveries joining the FIFO are fully
materialized with onward padding. Replay sends the initial body first, then hands
off the queued tail in order, coalescing multiple entries into one checked ordinary
buffer without callbacks during preparation. Temporary materialization/coalescing
storage is bounded scratch, not a promise about aggregate physical memory.

Replay waits for next-side permission. A Resume during Init only records that
permission; source Resume follows older startup output and is withheld while next
is paused. The barrier ends immediately before the final tail handoff, allowing
later reentrant data to follow all older bytes. Ready forwarding remains queue-free
and preserves ordinary/splice wrappers. Every close path releases main-owned
startup data and its budget before notifying adjacent sides.
