<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/PacketReceiver.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/PacketReceiver.mdx, and all files must keep the same documentation version.
-->

# PacketReceiver Node

`PacketReceiver` is an endpoint IPv4 packet counter. It groups packets by source IP and selected protocol number,
then writes a file report with per-IP totals, per-protocol counts, loss, and a text histogram.

## Example

```json
{
  "name": "packet-receiver",
  "type": "PacketReceiver",
  "settings": {
    "source-ipv4-range": [
      "8.8.8.0/24",
      "1.1.1.0/24"
    ],
    "protocol-number": ["TCP", "UDP", 253],
    "expected-packets-per-ip": 100,
    "report-after-ms": 7000,
    "output-file": "packet-receiver-report.txt"
  }
}
```

## Settings

- `source-ipv4-range`: required IPv4 CIDR range or list of ranges to track
- `protocol-number`: required `TCP`, `UDP`, `ICMP`, `ALL`, integer 0–255, or a nonempty mixed array of names and integers; duplicates are invalid, and `ALL` is valid only alone (selecting 0–254)
- `expected-packets-per-ip`: optional positive expected count per selected protocol and source IP, default `1`; received counts may exceed it
- `report-after-ms`: optional positive report delay, default `1000`; set it longer than the sender duration plus any expected tunnel delay/reordering window
- `output-file`: report path, default `packet-receiver-report.txt`

## Pairing With `PacketSender`

- For any sender mode, including `ALL`, set receiver `expected-packets-per-ip` to sender `packets-per-ip`.
- The receiver multiplies by the selected protocol count for expected totals, reports one total row per IP, and lists each selected protocol beneath it in array order (numeric order for `ALL`).
- Excess packets remain in received counts; loss is summed by protocol, so excess on one does not hide another's shortfall.

The report is written to the file only. PacketReceiver does not use packet-line `Finish` as a completion signal.
It can be placed at the end of a packet chain, where it consumes upstream payload, or at the start of a packet chain,
where it consumes downstream payload arriving from its next-side peer.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainHead` &#124; `kNodeFlagChainEnd` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` |
| `layer_group_prev_node` | `kNodeLayer3` |
| `layer_group_next_node` | `kNodeLayer3` |
| `required_padding_left` | `0` bytes |
