# PacketReceiver Node

`PacketReceiver` is an IPv4 packet-analysis sink that counts packets by source IP, compares the observed count against an expected per-IP send count, and writes a plain-text loss report with an ASCII histogram to a file.

It is designed to sit at the end of a packet-capable chain on the receive side, typically after `RawSocket`. For synthetic local tests, it can also be placed directly after `PacketSender`.

## What It Does

- acts as a chain-end packet analysis node
- accepts one or more IPv4 CIDR source ranges so it knows which source IPs to track
- counts incoming IPv4 packets by source IP
- compares the received count against `expected-packets-per-ip`
- records loss per source IP as both a number and a percentage
- writes a text histogram report to `output-file`
- does not print the histogram body to the console

## Typical Placement

A common receive-side layout is:

- `RawSocket -> PacketReceiver`

For direct synthetic checks inside one Waterwall process, you can also use:

- `PacketSender -> PacketReceiver`

## Configuration Example

```json
{
  "name": "packet-receiver",
  "type": "PacketReceiver",
  "settings": {
    "source-ip4-range": [
      "198.51.100.0/24",
      "203.0.113.0/24"
    ],
    "expected-packets-per-ip": 100,
    "output-file": "packet-receiver-report.txt"
  }
}
```

## Pairing With `PacketSender`

When you use `PacketReceiver` with `PacketSender`, set `expected-packets-per-ip` to match the sender-side packet
multiplier for each IP.

- If `PacketSender` uses a single protocol mode such as `TCP`, `UDP`, or `ICMP`, and `packets-per-ip` is `N`, then
  `expected-packets-per-ip` should also be `N`.
- If `PacketSender` uses `ALL`, each source IP produces `N * 255` packets, so `expected-packets-per-ip` should be
  `N * 255`.

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"PacketReceiver"`.

### `settings`

- `source-ip4-range` `(string or array of strings)`
  Required IPv4 CIDR range or ordered list of IPv4 CIDR ranges.

  The receiver uses this to build the list of source IPs that should appear in the report.

- `expected-packets-per-ip` `(integer)`
  Required positive packet count expected for each source IP.

  If the observed count is lower than this value, the report marks the difference as lost.

  In the report output, this is shown as the sent packet count per IP.

- `output-file` `(string)`
  Path of the report file.

  Default: `packet-receiver-report.txt`

## Detailed Behavior

### Counting

For every incoming IPv4 packet, `PacketReceiver` reads the packet source IP and increments that source's counter.

Packets that do not match one of the configured source IP ranges are tracked as unexpected packets in the summary.

### Loss evaluation

For each configured source IP, the report includes:

- expected packet count
- received packet count
- lost packet count
- loss percentage

The report defines loss as `expected - received` when the received value is lower than expected.

### Histogram output

The report contains a simple text histogram for every source IP.

The histogram is written only to `output-file`. It is not printed to the console.

### Report lifecycle

`PacketReceiver` writes the report when the runtime signals that all workers are done.
If the node is destroyed before that happens, it also writes a final snapshot so the file is still produced.

## Notes And Caveats

- `PacketReceiver` is IPv4-only.
- `source-ip4-range` should match the sender-side source list if you want loss numbers to line up.
- the report is text-only and intended for quick packet-analysis checks, not long-term metrics storage
