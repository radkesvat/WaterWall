<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/reverse-server.mdx, and both files must keep the same documentation version.
-->

# ReverseServer Node

`ReverseServer` is the server-side peer for `ReverseClient`. It receives pre-opened reverse connections from one side, receives real traffic from the other side, and pairs those two halves together so data can flow through the reverse tunnel.

In practice, this node is used on the reachable side of a reverse tunnel setup.

## What It Does

- Accepts pre-opened reverse connections coming from `ReverseClient`.
- Detects the internal reverse handshake on those connections.
- Keeps waiting reverse-side connections until a local peer is available.
- Keeps local peers until a reverse-side connection is available.
- Pairs one waiting reverse-side half with one waiting local half.
- Forwards payload, finish, pause, and resume between the paired halves.
- Can move a waiting reverse-side line to another worker when pairing requires it.

This node is neither a pure chain head nor a pure chain end. It sits between two sides of a chain and matches them dynamically.

## Typical Placement

A common setup is:

- transport/listener side feeding `ReverseServer` from the remote `ReverseClient`
- a `Bridge` near `ReverseServer` to connect the reverse side to another chain segment
- `ReverseServer`
- a paired `Bridge` near `ReverseClient` on the other side of the design
- some local-facing side on the other direction that represents the real inbound or outbound traffic you want to bridge

The important requirement is conceptual rather than positional: one side must carry `ReverseClient` reverse links, and the other side must carry the real peer traffic that should be attached to those links. In practice, this pairing is commonly attached with a named `Bridge` pair.

## Configuration Example

```json
{
  "name": "reverse-server",
  "type": "ReverseServer",
  "settings": {
    "reverse-secret-length": 640,
    "reverse-secret": "shared-secret"
  },
  "next": "next-node-name"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"ReverseServer"`.

- `next` `(string)`
  The next node on the side that carries the reverse links coming from `ReverseClient`.

### `settings`

The implementation works with an empty `settings` object. Optional fields tune
the reverse-link handshake signature.

## Optional `settings` Fields

- `reverse-secret-length` `(integer)`
  Overrides the reverse handshake length.

  Default: `640`

  This value must be in range `1` to `1024`.

- `reverse-secret` `(string)`
  Changes the expected reverse handshake bytes by XORing the default handshake
  bytes with the ASCII bytes of this string repeatedly.

  `ReverseServer`, `ReverseClient`, and any `SniffRouter` reverse route in front
  of them must use the same `reverse-secret-length` and `reverse-secret`.

## Detailed Behavior

### Two-sided matching model

`ReverseServer` works by pairing two different kinds of half-connections:

- reverse-side connections coming from `ReverseClient`
- local-side connections coming from the other side of the chain

The reverse-side half is recognized by an internal handshake. By default this is
`640` bytes of value `0xFF`; with `reverse-secret`, those default bytes are XORed
with the secret bytes repeatedly.

### Reverse-side handshake processing

When payload arrives from the reverse side before pairing:

- payload is buffered until enough bytes are available to validate the complete
  reverse handshake
- if the handshake is invalid, that half-connection is dropped
- if the handshake is valid, the handshake bytes are removed
- the reverse-side half is placed into a waiting list
- any payload after the handshake is kept as buffered data until pairing happens

### Local-side waiting behavior

When payload arrives from the local side before pairing:

- the local half is marked as available
- it is placed into a waiting list
- its first payload is buffered if no reverse-side peer is ready yet

Once a peer becomes available, the waiting halves are paired and any buffered first payloads are forwarded.

### Pairing behavior

After pairing:

- reverse-side payload is forwarded to the local side
- local-side payload is forwarded to the reverse side
- finish events close the peer half as well
- pause and resume are forwarded across the pair

If both sides already have buffered payload, those buffered chunks are delivered immediately after the pair is formed.

### Cross-worker pairing

`ReverseServer` keeps waiting lists per worker. If a reverse-side half arrives on a worker that has no local peer waiting, the tunnel can move that reverse-side line to another worker using an internal pipe tunnel layer and then complete the pairing there.

This is an implementation detail, but it matters because it allows reverse links and local peers to be matched even when they are not created on the same worker thread.

### Buffering limits

Each unpaired half can buffer data while waiting for its peer.

Current limit:

- about `64 KB` maximum buffered data per waiting half

If that limit is exceeded, the waiting half is dropped.

### Establishment semantics

`ReverseServer` does not use normal `est` callbacks in the same way as simple listener/connector tunnels.

Instead:

- when a reverse-side line is initialized, it immediately reports downstream establishment to the previous side
- actual useful forwarding starts only after the reverse handshake is validated and a peer is paired

## Notes And Caveats

- `reverse-secret-length` and `reverse-secret` must match the peer
  `ReverseClient` and any `SniffRouter` reverse detector in front of it.
- It is tightly coupled to `ReverseClient` through the shared handshake format.
- Unpaired halves can be buffered temporarily, but large buffered payloads are dropped once they exceed the per-half limit.
