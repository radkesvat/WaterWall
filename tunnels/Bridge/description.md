<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/Bridge.mdx, and both files must keep the same documentation version.
-->

# Bridge Node

`Bridge` links two separate places in the same WaterWall configuration. A pair of `Bridge` nodes forwards line events and payload between each other, effectively stitching two otherwise separate chain segments together.

In practice, `Bridge` is commonly used together with `ReverseClient` and `ReverseServer` so that the reverse side and the local service side can be connected through a named bridge pair.

## What It Does

- Pairs itself with another node by name.
- Forwards upstream events arriving on one bridge into the paired bridge's previous side.
- Forwards downstream events arriving on one bridge into the paired bridge's next side.
- Relays `init`, `est`, `payload`, `finish`, `pause`, and `resume` without adding its own protocol.

This node is a pure relay. It does not create its own transport and it does not parse payload.

## Typical Placement

`Bridge` is intended to be used as a pair.

A common reverse-tunnel layout is:

- one `Bridge` near `ReverseClient`
- one `Bridge` near `ReverseServer`
- each bridge points at the other by name
- the reverse half of the chain is connected on one side of the pair
- the local service half of the chain is connected on the other side

That is why `ReverseClient` and `ReverseServer` are typically described together with `Bridge`: the bridge pair is what makes it easy to attach the reverse tunnel to another chain segment.

## Configuration Example

Bridge A:

```json
{
  "name": "bridge-a",
  "type": "Bridge",
  "settings": {
    "pair": "bridge-b"
  },
  "next": "some-next-node"
}
```

Bridge B:

```json
{
  "name": "bridge-b",
  "type": "Bridge",
  "settings": {
    "pair": "bridge-a"
  },
  "next": "another-next-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this bridge node.

- `type` `(string)`
  Must be exactly `"Bridge"`.

### `settings`

- `pair` `(string)`
  The name of the other bridge node.

  The named node must exist in the same loaded configuration and must already be instantiated by the node manager.

## Detailed Behavior

### Pairing model

When the tunnel chain is being wired up, `Bridge` resolves the configured `pair` node name and stores the paired tunnel instance. The first bridge to finish chaining also sets the reverse pointer on the other bridge.

After that, both bridges can relay line events into each other.

### Event forwarding behavior

For a line arriving at one bridge:

- upstream `init` is forwarded as downstream `init` into the paired bridge's previous side
- upstream `est` is forwarded as downstream `est`
- upstream `payload` is forwarded as downstream `payload`
- upstream `finish` is forwarded as downstream `finish`
- upstream `pause` is forwarded as downstream `pause`
- upstream `resume` is forwarded as downstream `resume`

And in the other direction:

- downstream `init` is forwarded as upstream `init` into the paired bridge's next side
- downstream `est` is forwarded as upstream `est`
- downstream `payload` is forwarded as upstream `payload`
- downstream `finish` is forwarded as upstream `finish`
- downstream `pause` is forwarded as upstream `pause`
- downstream `resume` is forwarded as upstream `resume`

So `Bridge` does not modify the line. It just reroutes the callback flow through its partner.

### Why it helps with reverse tunnels

`ReverseClient` and `ReverseServer` handle reverse-link creation and pairing, but they do not by themselves explain where the "other side" of the local traffic should be attached.

A bridge pair solves that by letting you place:

- one side of the system near the reverse transport
- another side near the local-facing chain

and then connect those two places logically through the bridge pair.

## Notes And Caveats

- `Bridge` is intended to be paired with another `Bridge` node.
- The current implementation requires the paired node name to exist in the same configuration.
- `Bridge` adds no buffering, protocol parsing, or transport of its own. It only relays events.
