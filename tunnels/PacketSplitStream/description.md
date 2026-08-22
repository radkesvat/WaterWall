<!--
Documentation version: 152
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/PacketSplitStream.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/PacketSplitStream.mdx, and all files must keep the same documentation version.
-->

# PacketSplitStream Node

`PacketSplitStream` takes one worker packet line from the left side and splits it into two persistent stream-facing lines:

- an `up` line used only for sending packet payload upstream
- a `down` line used only for receiving payload back from the right side

Unlike `HalfDuplexClient`, this tunnel is packet-line anchored and does not do pairing or handshake restoration. It just keeps two worker-local split lines alive behind each packet line.

## Required Settings

```json
{
  "name": "splitter",
  "type": "PacketSplitStream",
  "settings": {
    "up": "upload-branch-head",
    "down": "download-branch-head"
  }
}
```

- `settings.up`: node name used as the upstream entry tunnel for sent packets
- `settings.down`: node name chained as the normal downstream branch for received packets

Top-level `next` is intentionally unused for this tunnel in configuration.

During chain construction, `PacketSplitStream` binds its configured `down` branch as its chained `next` tunnel (`tunnelBind(t, state->down_tunnel)`), allowing it to receive return packets flowing downstream from the `down` node. Consequently, `can_have_next` is `true` and `layer_group_next_node` is `kNodeLayer3`.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainEnd` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` |
| `layer_group_prev_node` | `kNodeLayer3` |
| `layer_group_next_node` | `kNodeLayer3` |
| `required_padding_left` | `0` bytes |
