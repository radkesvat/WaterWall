<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/halfduplex-server.mdx, and both files must keep the same documentation version.
-->

# HalfDuplexServer Node

`HalfDuplexServer` is the server-side peer of `HalfDuplexClient`. It receives two separate inbound half-connections, matches them by an internal identifier, and reconstructs one normal logical line toward the next node.

In practice, this node is used together with `HalfDuplexClient` on the other side of the transport.

## What It Does

- Accepts inbound half-connections from the previous node.
- Reads an internal 8-byte intro to decide whether each connection is an upload or download side.
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

`HalfDuplexServer` waits until it has at least 8 bytes, then reads the internal identifier block sent by `HalfDuplexClient`.

From that block it extracts:

- the logical connection hash
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

- the 8-byte intro
- the user's first real payload after that intro

When pairing succeeds, `HalfDuplexServer` strips the intro bytes and forwards any remaining upload payload to the newly created main line.

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

- `65535 * 2` bytes

If that limit is exceeded before the matching download half appears, the waiting upload line is closed.

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
- The tunnel depends on an internal 8-byte intro shared with `HalfDuplexClient`.
- Waiting upload halves can buffer data, but waiting download halves are mostly just registered in the map.
- The current implementation uses a pipe-tunnel wrapper internally for cross-worker pairing.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.
