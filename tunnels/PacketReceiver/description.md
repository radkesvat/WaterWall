<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/packet-receiver.mdx, and both files must keep the same documentation version.
-->

# PacketReceiver Node

`PacketReceiver` is an endpoint IPv4 packet counter. It groups packets by source IP, compares them against an expected
per-IP count, and writes a file report with loss and a text histogram.

## Example

```json
{
  "name": "packet-receiver",
  "type": "PacketReceiver",
  "settings": {
    "source-ip4-range": [
      "8.8.8.0/24",
      "1.1.1.0/24"
    ],
    "expected-packets-per-ip": 100,
    "report-after-ms": 7000,
    "output-file": "packet-receiver-report.txt"
  }
}
```

## Settings

- `source-ip4-range`: required IPv4 CIDR range or list of ranges to track
- `expected-packets-per-ip`: required positive count expected for each source IP
- `report-after-ms`: optional positive report delay, default `1000`; set it longer than the sender duration plus any expected tunnel delay/reordering window
- `output-file`: report path, default `packet-receiver-report.txt`

## Pairing With `PacketSender`

- `TCP`, `UDP`, or `ICMP`: set this to the sender `packets-per-ip`
- `ALL`: set this to `packets-per-ip * 255`

The report is written to the file only. PacketReceiver does not use packet-line `Finish` as a completion signal.
It can be placed at the end of a packet chain, where it consumes upstream payload, or at the start of a packet chain,
where it consumes downstream payload arriving from its next-side peer.
