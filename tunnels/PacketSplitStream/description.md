<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/PacketSplitStream.mdx, and both files must keep the same documentation version.
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

Top-level `next` is intentionally unused for this tunnel.
