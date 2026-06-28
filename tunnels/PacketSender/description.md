<!--
Documentation version: 107
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/PacketSender.mdx, and both files must keep the same documentation version.
-->

# PacketSender Node

`PacketSender` is a layer-3 IPv4 packet generator. It pre-builds packets at startup and sends them across the worker
packet lines during the configured duration.

## Core Behavior

- chain head only
- accepts one or more IPv4 source ranges and one destination IPv4 address
- `packets-per-ip` repeats each source IP `N` times, default `1`
- `ALL` mode still emits `255` protocol variants per repeat
- source ranges are processed in order and are not interleaved
- prebuilt packet storage is capped at `8 GiB` and also must fit in the platform `size_t` address space
- does not close or finish worker packet lines after sending

## Example

```json
{
  "name": "packet-sender",
  "type": "PacketSender",
  "settings": {
    "source-ip4-range": [
      "8.8.8.0/24",
      "1.1.1.0/24"
    ],
    "dest-ipv4": "203.0.113.20",
    "protocol-number": "ICMP",
    "duration-ms": 5000,
    "packets-per-ip": 100
  },
  "next": "raw-ip"
}
```

## Settings

- `source-ip4-range`: required IPv4 CIDR range or list of ranges
- `packets-per-ip`: optional positive integer, default `1`
- `dest-ipv4`: required destination IPv4 address
- `protocol-number`: `TCP`, `UDP`, `ICMP`, or `ALL`
- `duration-ms`: required positive duration in milliseconds
- `dest-port`: required for `TCP`, `UDP`, or `ALL`
- `src-port`: required for `TCP`, `UDP`, or `ALL`

## Note

When `protocol-number` is `ALL`, the total packets per source IP become `packets-per-ip * 255`.
PacketSender materializes its packet store before sending, so large ranges and high repeat counts must fit under the
`8 GiB` safety cap.
