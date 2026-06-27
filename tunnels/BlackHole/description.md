<!--
Documentation version: 107
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/BlackHole.mdx, and both files must keep the same documentation version.
-->

# BlackHole Node

`BlackHole` is a terminal sink adapter. It is placed at the end of a chain and consumes upstream traffic from the previous node without creating a socket, connecting to a remote peer, or forwarding payload to another node.

It supports two behaviors:

- `passive` mode accepts the line, reports downstream `Est` to the previous side, and silently drops upstream payload
- `active` mode immediately sends downstream `Finish` to the previous side during upstream `Init`

Because `BlackHole` is an adapter, downstream callbacks are not part of its valid runtime surface. Do not place another node after it.

## What It Does

- can be used as the last node in a chain
- rejects configuration with a `next` node
- drops every upstream payload buffer it receives
- recycles dropped payload buffers with `lineReuseBuffer()`
- does not prepend, frame, encrypt, decode, or rewrite payload
- does not allocate per-line tunnel state
- does not change buffer padding requirements
- does not create or destroy packet lines

## Typical Placement

Common examples:

- `TcpListener <--> BlackHole`
- `UdpListener <--> BlackHole`
- policy or test chains where accepted traffic should be consumed or rejected at the chain end

`BlackHole` is not a middle tunnel. For a chain such as `TcpListener <--> BlackHole <--> TcpConnector`, use another policy or routing tunnel instead.

## Configuration Example

### Passive mode

```json
{
  "name": "blackhole-passive",
  "type": "BlackHole",
  "settings": {
    "mode": "passive"
  }
}
```

Equivalent passive aliases:

- `passive`
- `drop`
- `packet-drop`
- `silent`
- `calm`

### Active mode

```json
{
  "name": "blackhole-active",
  "type": "BlackHole",
  "settings": {
    "mode": "active"
  }
}
```

Equivalent active aliases:

- `active`
- `close`
- `aggressive`
- `kill`
- `kill-connection`

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen node name.

- `type` `(string)`
  Must be exactly `"BlackHole"`.

### `settings`

`settings` must contain:

- `mode` `(string)`

`next` must not be configured. `BlackHole` is a chain-end adapter.

## `mode` Meaning

### `passive`

In passive mode:

- upstream `Init` sends downstream `Est` to the previous side
- upstream payload is dropped and recycled
- upstream `Est`, `Finish`, `Pause`, and `Resume` are no-ops
- downstream callbacks are disabled by the adapter edge

Passive mode does not close the line by itself. It consumes payload until the previous side closes the line.

### `active`

In active mode:

- upstream `Init` sends downstream `Finish` to the previous side and returns immediately
- upstream payload is still dropped and recycled if any payload reaches the node
- downstream callbacks are disabled by the adapter edge

This behaves like an immediate connection reject at the end of the chain.

## Detailed Behavior

### Payload handling

Upstream payload calls `lineReuseBuffer()` on the received buffer and returns.

That means:

- no payload is forwarded
- buffer ownership stays correct
- no extra framing or padding assumptions are introduced

### Lifecycle handling

`BlackHole` follows downstream-end adapter direction rules:

- it receives upstream callbacks from the previous node
- it may send downstream callbacks back toward the previous node
- it never calls `tunnelNextUpStream*()` because there is no next node
- downstream callbacks into `BlackHole` are invalid and blocked by `adapterCreate()`

## Notes And Caveats

- `required_padding_left = 0`.
- `kLineStateSize = 0`; the node has no per-line tunnel state.
- `BlackHole` is layer-agnostic in node metadata, but it does not transform between stream and packet semantics.
- `passive` mode can leave the previous side open indefinitely if that side keeps the line open.
- `active` mode is best used as a deliberate reject or kill endpoint.
