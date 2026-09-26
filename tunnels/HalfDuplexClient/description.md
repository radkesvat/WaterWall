<!--
Documentation version: 159
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/HalfDuplexClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/HalfDuplexClient.mdx, and all files must keep the same documentation version.
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

Each logical pair receives a fresh 128-bit identifier from the fast CSPRNG.

On the first upstream payload only:

- `HalfDuplexClient` creates a 17-byte intro containing one exact role command
  followed by the 16-byte pair identifier
- sends the download-role copy by itself on the download line
- prefixes the upload-role copy to the user's first real payload on the upload line

After that first payload:

- all further upstream payload goes only through the upload line
- downstream payload is expected to come back through the download line

So the remote `HalfDuplexServer` learns that the two incoming transport lines belong to the same logical connection.
The identifier is internal routing metadata. It does not authenticate either
half or protect the transport; configure security nodes when those properties
are required.

### Data flow direction

- Local upstream payload: previous node -> `HalfDuplexClient` -> upload line -> next node
- Remote downstream payload: next node -> download line -> `HalfDuplexClient` -> previous node

The upload line is used for normal client-to-server data.

The download line exists mainly so the remote side has a dedicated return path for server-to-client data.

### Establishment, ordering and close

Transport Est from either child is forwarded to the main application exactly once,
using this node's notification latch. A synchronous Est inside the first child's
Init waits only until both adjacent child Init calls have admitted their identities;
there is no pairing-handshake gate. Valid payload after that Init can proceed before
Est. An Est callback can safely submit the first payload or close the pair.

Only temporary Init/intro ordering input is retained, with a 2 MiB / 1,024-buffer
inclusive bound. First-intro publication precedes callbacks, and input nested during
the download intro follows the older upload intro with the same pair ID. An admitted
input can finish through Pause. A later release of Init backlog respects aggregate
child pressure; one child Resume cannot clear another child's outstanding Pause.
Application read Pause received before the download child exists is applied after
its Init. Ready payload otherwise forwards directly without a transport queue.

Before any outward Finish, all pair links and local state are detached. The client
synchronously closes both owned children, retaining exact lines across callbacks;
received Finish is never reflected toward its sender. The borrowed main line is
finished through its owner. No detached child waits on a cancelable close task.

## Notes And Caveats

- `HalfDuplexClient` is intended to be paired with `HalfDuplexServer`.
- There are no tunnel-specific JSON settings today.
- The first upstream payload is special because it carries the pairing intro for the upload side.
- The intro is exactly 17 bytes: one role byte and one fresh 128-bit pair ID.
- The download line sends only the intro at startup and is then used mainly for return traffic.
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
| `required_padding_left` | `17` bytes |

## Splice and setup storage

The first upstream delivery, including an empty delivery, triggers both 17-byte
intros with the same 128-bit pair ID. The upload intro and the entire first body
are combined into one ordinary buffer. Ordinary input with enough advertised
headroom is reused in place; insufficient headroom uses a new buffer. Splice
input is fully materialized, preserving its resident prefix and private-pipe
body in order. The download intro is ordinary too. Later upstream and
downstream deliveries preserve their original ordinary or splice representation.
The temporary Init/intro FIFO can retain splice wrappers without materializing
them; its inclusive 2 MiB and 1,024-buffer limits are unchanged and do not cap
every ready delivery. Allocated outputs retain onward padding.

Both nodes advertise `kNodeFlagSupportsSplice`. The client requires 17 bytes of
left padding for its upload intro; the server requires zero.
Actual splice reads require platform/build support, `misc.splice` enabled, and
support from every node in the expanded chain, including the server's PipeTunnel
wrapper and all neighbors. Ordinary buffers remain valid in every state. No new
settings, wire fields, or read-preference requests are introduced.
