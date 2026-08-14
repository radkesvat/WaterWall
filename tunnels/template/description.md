# Template Node

`Template` is the starter tunnel skeleton used for building new Waterwall tunnels.

In its current form it is just a pass-through node:

- upstream callbacks are forwarded to the next tunnel
- downstream callbacks are forwarded to the previous tunnel
- it has no real state, no JSON settings, and no payload transformation

This folder is mainly for developers, not for production use.

## What It Does

- Shows the standard Waterwall tunnel file layout.
- Wires all normal callbacks in `instance/create.c`.
- Provides stub tunnel state and line state structs.
- Forwards every lifecycle and payload callback unchanged.

## Typical Placement

You normally do not place `Template` in a real deployment.

Instead, you copy or rename it when creating a new tunnel implementation and then replace the stub behavior with real logic.

If you do instantiate it as-is, it behaves like a no-op relay in the chain.

## Configuration Example

```json
{
  "name": "template-node",
  "type": "Template",
  "next": "next-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"Template"`.

### `settings`

There are no tunnel-specific settings in the current implementation.

## Detailed Behavior

### Current callback behavior

The current files are intentionally minimal:

- upstream `Init` calls `tunnelNextUpStreamInit()`
- upstream `Est` calls `tunnelNextUpStreamEst()`
- upstream `Payload` calls `tunnelNextUpStreamPayload()`
- upstream `Finish` calls `tunnelNextUpStreamFinish()`
- upstream `Pause` and `Resume` forward unchanged

And in the other direction:

- downstream `Init` calls `tunnelPrevDownStreamInit()`
- downstream `Est` calls `tunnelPrevDownStreamEst()`
- downstream `Payload` calls `tunnelPrevDownStreamPayload()`
- downstream `Finish` calls `tunnelPrevDownStreamFinish()`
- downstream `Pause` and `Resume` forward unchanged

So as shipped, `Template` is effectively a transparent relay.

### State layout

Both state structs contain only placeholder fields:

- `template_tstate_t`
- `template_lstate_t`

The helper and line-state files are also just stubs.

Current defaults:

- `required_padding_left = 0`
- no JSON parsing
- no tunnel-specific start or prepare behavior

### Stop lifecycle

The framework supplies a no-op `onPreStop` by default. A tunnel that starts
producers should override it to close admission and quiesce new callbacks. The
node manager completes this pre-stop pass across every configuration before any
`onStop` hook runs. `onStop` may then join, detach, and release shared resources,
but it must also remain safe when partial-start cleanup reaches it without the
global prepass. Worker-local `onWorkerStop` teardown is a separate phase.

### Why this folder matters

The useful part of `Template` is the project structure it demonstrates:

- `instance/` for construction, destruction, indexing, chaining, prepare, and start hooks
- `upstream/` for upstream lifecycle and payload callbacks
- `downstream/` for downstream lifecycle and payload callbacks
- `common/` for shared helpers and line-state utilities
- `include/` for exported structure definitions

That layout matches the rest of the Waterwall tunnels directory.

## Developer Notes

If you use this folder as the base for a new tunnel, remember the core Waterwall rules:

- upstream talks to `tunnelNext*`
- downstream talks to `tunnelPrev*`
- destroy per-line state before propagating `Finish`
- protect lines around re-entrant callbacks with `withLineLocked()` or manual `lineLock()` and `lineUnlock()`
- do not access line state after a callback path that may have closed the line
- if your tunnel prepends bytes, update `required_padding_left` in `instance/node.c`

## Notes And Caveats

- `Template` is scaffolding, not a feature tunnel.
- As currently implemented it adds no buffering, framing, protocol handling, or stateful behavior.
