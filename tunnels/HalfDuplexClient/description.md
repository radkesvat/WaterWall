<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/halfduplex-client.mdx, and both files must keep the same documentation version.
-->

# HalfDuplexClient Node

`HalfDuplexClient` takes one normal full-duplex line from the previous node and splits it into two separate outbound connections toward the next node:

- one upload connection for client-to-server payload
- one download connection for server-to-client payload

In practice, this node is used together with `HalfDuplexServer` on the remote side.

## What It Does

- Accepts one normal line from the previous node.
- Creates two outbound lines through the next node.
- Uses the first payload to introduce and pair the two half-connections.
- Sends all later upstream payload only on the upload connection.
- Receives downstream payload back from the download connection and forwards it to the previous node.
- Closes both half-connections when the original line closes.

This tunnel is useful when the transport path or remote layout wants separate flows for upload and download instead of one bidirectional connection.

## Typical Placement

A common layout is:

- some normal stream-producing or stream-consuming node before `HalfDuplexClient`
- `HalfDuplexClient`
- a transport path that can create two outbound connections
- `HalfDuplexServer` on the remote side
- normal service-facing nodes after `HalfDuplexServer`

This pair behaves like an adapter between one local full-duplex line and two remote half-duplex transport lines.

## Configuration Example

```json
{
  "name": "halfduplex-client",
  "type": "HalfDuplexClient",
  "settings": {},
  "next": "outbound-transport"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"HalfDuplexClient"`.

- `next` `(string)`
  The next node that should create the two outbound half-connections.

### `settings`

There are no required tunnel-specific settings in the current implementation.

## Optional `settings` Fields

There are no tunnel-specific optional settings in the current implementation.

## Detailed Behavior

### Line splitting model

When a new line arrives from the previous node, `HalfDuplexClient` creates:

- one upload line
- one download line

Both are initialized through the next node on the same worker.

The original local line remains the main line. Its line state keeps references to the two transport-side half-connections.

### Pairing handshake

The pair is identified by an internal 64-bit identifier generated from the tunnel's atomic counter.

On the first upstream payload only:

- `HalfDuplexClient` creates an 8-byte identifier block
- marks one copy as a download-intro command
- sends that command by itself on the download line
- marks the other copy as an upload-intro command
- prefixes it to the user's first real payload on the upload line

After that first payload:

- all further upstream payload goes only through the upload line
- downstream payload is expected to come back through the download line

So the remote `HalfDuplexServer` learns that the two incoming transport lines belong to the same logical connection.

### Data flow direction

- Local upstream payload: previous node -> `HalfDuplexClient` -> upload line -> next node
- Remote downstream payload: next node -> download line -> `HalfDuplexClient` -> previous node

The upload line is used for normal client-to-server data.

The download line exists mainly so the remote side has a dedicated return path for server-to-client data.

### Establishment behavior

If either half-connection becomes established through the next node, `HalfDuplexClient` marks the original main line established toward the previous node.

That means the local side sees one logical line even though the tunnel has created two transport-side lines behind it.

### Pause and resume behavior

When the previous node pauses or resumes the logical line, `HalfDuplexClient` forwards that control to the download line.

When downstream pause or resume comes back from the remote side, `HalfDuplexClient` forwards it to the original main line.

This matches the intended data ownership:

- upload line mainly carries upstream data
- download line mainly carries downstream data

### Finish behavior

If the original main line finishes, `HalfDuplexClient` closes both transport-side half-connections.

If either transport-side half-connection finishes first, `HalfDuplexClient` also finishes the original main line and schedules the other half-connection to close.

## Notes And Caveats

- `HalfDuplexClient` is intended to be paired with `HalfDuplexServer`.
- There are no tunnel-specific JSON settings today.
- The first upstream payload is special because it carries the pairing intro for the upload side.
- The download line sends only the intro at startup and is then used mainly for return traffic.
- `UpStreamEst` and `DownStreamInit` are disabled in the current implementation.
