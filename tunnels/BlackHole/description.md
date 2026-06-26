<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/black-hole.mdx, and both files must keep the same documentation version.
-->

# BlackHole Node

`BlackHole` is a sink tunnel that keeps normal Waterwall line flow but suppresses payload.

It supports two behaviors:

- `passive` mode keeps the line alive and forwards lifecycle callbacks, but drops payload in both directions
- `active` mode lets upstream `Init` happen, then immediately closes the line and still drops payload

This makes it useful when you want a chain stage that either absorbs traffic silently or kills connections quickly without inventing a custom adapter lifecycle.

## What It Does

- does not prepend, frame, or rewrite payload
- does not change buffer padding requirements
- drops every payload buffer it receives
- preserves normal direction ownership for non-payload callbacks
- can either keep the line structurally alive (`passive`) or close it immediately after startup (`active`)

## Typical Placement

Common examples:

- `TcpListener <--> BlackHole <--> TcpConnector`
- `UdpListener <--> BlackHole <--> UdpConnector`
- test or policy chains where one stage should consume traffic without forwarding application data

`BlackHole` is a middle tunnel, not a socket adapter.

## Configuration Example

### Passive mode

```json
{
  "name": "blackhole-passive",
  "type": "BlackHole",
  "settings": {
    "mode": "passive"
  },
  "next": "next-node"
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
  },
  "next": "next-node"
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

## `mode` Meaning

### `passive`

In passive mode:

- upstream `Init`, `Est`, `Finish`, `Pause`, and `Resume` are forwarded normally
- downstream `Init`, `Est`, `Finish`, `Pause`, and `Resume` are forwarded normally
- upstream payload is dropped
- downstream payload is dropped

So the line can still open, establish, pause, resume, and close through the chain, but no application payload crosses this tunnel.

### `active`

In active mode:

- per-line state is initialized during upstream `Init`
- upstream `Init` is still forwarded first
- then `BlackHole` immediately closes upstream and downstream
- payload is still dropped in both directions if any payload reaches it

This behaves like an immediate connection kill after startup rather than a silent sink.

## Detailed Behavior

### Payload handling

Both directions call `lineReuseBuffer()` on received payload and return.

That means:

- no payload is forwarded
- buffer ownership stays correct
- no extra framing or padding assumptions are introduced

### Lifecycle handling

`BlackHole` keeps normal Waterwall callback direction rules:

- upstream control flow uses `tunnelNext*`
- downstream control flow uses `tunnelPrev*`

In `active` mode it protects the line across re-entrant startup and close callbacks before issuing the immediate finishes.

## Notes And Caveats

- `BlackHole` does not require extra left padding.
- `passive` mode drops payload but does not itself close lines.
- `active` mode is intentionally implemented as `upstream Init` followed by immediate close.
- It does not synthesize a downstream `Init`, because common Waterwall stream adapters do not accept `DownStreamInit`.
