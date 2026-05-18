# PacketReceiver Node

`PacketReceiver` is a chain-end IPv4 packet counter. It groups packets by source IP, compares them against an expected
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
    "output-file": "packet-receiver-report.txt"
  }
}
```

## Settings

- `source-ip4-range`: required IPv4 CIDR range or list of ranges to track
- `expected-packets-per-ip`: required positive count expected for each source IP
- `output-file`: report path, default `packet-receiver-report.txt`

## Pairing With `PacketSender`

- `TCP`, `UDP`, or `ICMP`: set this to the sender `packets-per-ip`
- `ALL`: set this to `packets-per-ip * 255`

The report is written to the file only.
