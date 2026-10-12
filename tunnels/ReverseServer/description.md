<!--
Documentation version: 156
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/ReverseServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/ReverseServer.mdx, and all files must keep the same documentation version.
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

The reverse-link transport/listener feeds `ReverseServer`, whose next node must be the `Bridge` connecting it to the local/user traffic branch: `ReverseServer -> Bridge`. No node may intervene between them. The companion client-side rule is `Bridge -> ReverseClient`, also with no intervening nodes.

These are chain-design requirements that users must follow; the code does not automatically enforce either adjacency rule. One side carries `ReverseClient` reverse links, while the paired Bridge branch carries the real peer traffic to attach to those links.

## Configuration Example

```json
{
  "name": "reverse-server",
  "type": "ReverseServer",
  "settings": {
    "reverse-secret-length": 640,
    "reverse-secret": "shared-secret"
  },
  "next": "bridge-reverse"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"ReverseServer"`.

- `next` `(string)`
  The directly adjacent `Bridge` leading to the local/user traffic branch. No intervening node is allowed.

### `settings`

The implementation works with an empty `settings` object. Optional fields tune
the reverse-link handshake signature.

## Optional `settings` Fields

- `activation-min-size` `(integer)`: minimum total activation size, default `64`.
- `activation-max-size` `(integer)`: maximum total activation size, default `1024`.

Both include the four-byte header, accept `4..65536`, and require `min <= max`.
Configure this range only on ReverseServer.

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

- handshake bytes are compared incrementally; only the matched offset is retained
- if the handshake is invalid, that half-connection is dropped
- if the handshake is valid, the handshake bytes are removed
- the reverse-side half is placed into a waiting list
- any payload after the handshake is kept as buffered data until pairing happens

### Local-side waiting behavior

A local/user half enters the waiting list during Init and attempts pairing without
waiting for application data. Early payload is retained under the existing waiting
limit until an authenticated reverse peer is available. An existing application
backlog remains queued after pairing while its consumer is paused.
After Est, an unpaired user source is paused. A fully authenticated reverse source
is also held while unpaired. Pairing sends activation and drains eligible older
bytes before releasing these holds. Consumer Pause keeps its source held; clearing
a waiting hold never overrides it. Holds and consumer pressure survive migration.

### Variable-size activation

A pair sends exactly one activation prefix before any user application bytes:

```text
4-byte big-endian total length | random padding | direct application stream
```

The total length includes the four-byte header and is in `4..65536`. Each pair
chooses a fresh random length between `activation-min-size` (default `64`) and
`activation-max-size` (default `1024`), inclusive. Both settings belong only to
ReverseServer; ReverseClient reads the advertised length without knowing the
configured range. Values must be integers in `4..65536`, with `min <= max`.

ReverseClient consumes the complete prefix, then opens its destination line.
No user payload is required, so a destination greeting can reach a silent user.
The prefix is also sent for users that send immediately; it always precedes
application data and never reaches the destination. There are no later activation
headers. Fragmentation and a prefix coalesced with application data are supported.

ReverseServer hands off activation once even if the reverse side is paused, in a
separate buffer containing no application data. Buffered application bytes still
wait for Resume. The receiving transport may queue activation until it can write.

Random lengths avoid one fixed activation size. The plaintext length field and
traffic timing remain visible without an enclosing encrypted transport; this is
not a guarantee against traffic fingerprinting.

### Pairing behavior

After pairing:

- reverse-side payload is forwarded to the local side
- local-side payload is forwarded to the reverse side
- finish events close the peer half as well
- pause and resume are forwarded across the pair

Buffered application bytes preserve FIFO order during activation and initial replay.
Retained application output waits for Resume when its consumer is paused; ready
payloads continue to use direct forwarding.

### Cross-worker pairing

A newly initialized user notifies the worker of an already waiting reverse peer, so either arrival order can pair without new payload. Notifications carry no foreign line pointer.

`ReverseServer` keeps waiting lists per worker. If a reverse-side half arrives on a worker that has no local peer waiting, the tunnel can move that reverse-side line to another worker using an internal pipe tunnel layer and then complete the pairing there.

This is an implementation detail, but it matters because it allows reverse links and local peers to be matched even when they are not created on the same worker thread.

### Buffering limits

Each half has one application FIFO with inclusive limits of **2 MiB logical bytes
and 1,024 buffers**, independent of the RAM profile. Waiting data and retained
startup replay share that budget. Empty TCP input consumes no entries; handshake
comparison state and the separate activation prefix are protocol metadata.

A refused admission closes the waiting half, or both halves if already paired.
Ready direct payloads do not acquire a backlog or inherit its size limit.

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

## Splice Support

ReverseServer materializes each complete splice payload into ordinary memory in
both directions while the half is unpaired. This covers handshake validation,
handshake removal, waiting FIFOs and replay when pairing moves to another
worker. Handshake completion alone does not end materialization: waiting storage
remains ordinary until pairing completes. Initial replay and input queued behind
startup backlog also use ordinary storage. Ready paired payloads pass through
unchanged in both directions.

The internal PipeTunnel shares ReverseServer's splice capability and transfers
opaque payload buffers across workers. Existing waiting limits, callback mapping
and direct `ReverseServer -> Bridge` placement still apply. Splice activation
requires an eligible finalized chain and `misc.splice`.

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

Application retention uses the same 2 MiB / 1,024-buffer limits in every RAM profile.
