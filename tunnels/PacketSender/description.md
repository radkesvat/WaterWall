# PacketSender Node

`PacketSender` is an IPv4-only synthetic packet adapter that acts as a layer-3 chain head. It pre-generates a packet
store at startup and then schedules those packets smoothly across the configured duration on the chain's worker packet
lines.

It is meant for one-way packet generation toward another packet-capable adapter such as `RawSocket`.
It can also accept multiple IPv4 source ranges and walk them in order, finishing one range before moving to the next.

## What It Does

- acts as a chain-head packet adapter
- accepts one or more IPv4 CIDR source ranges and one IPv4 destination
- pre-generates every packet before transmission begins
- sends packets on the upstream path with `tunnelNextUpStreamPayload()`
- never closes the shared worker packet lines during normal runtime
- drops any unexpected downstream payload because it has no external return side

## Typical Placement

A common layout is:

- `PacketSender -> RawSocket`

You can also place packet-only middle tunnels between them, for example:

- `PacketSender -> IpManipulator -> RawSocket`

`PacketSender` must be the chain head.

## Configuration Example

TCP-only:

```json
{
  "name": "packet-sender",
  "type": "PacketSender",
  "settings": {
    "source-ip4-range": [
      "198.51.100.0/24",
      "203.0.113.0/24"
    ],
    "dest-ip4": "203.0.113.20",
    "protocol-number": "TCP",
    "duration-ms": 5000,
    "dest-port": 443,
    "src-port": "random"
  },
  "next": "raw-ip"
}
```

All protocols:

```json
{
  "name": "packet-sender",
  "type": "PacketSender",
  "settings": {
    "source-ip4-range": "198.51.100.0/25",
    "dest-ip4": "203.0.113.20",
    "protocol-number": "ALL",
    "duration-ms": 10000,
    "dest-port": 443,
    "src-port": 50000
  },
  "next": "raw-ip"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"PacketSender"`.

- `next` `(string)`
  The next packet-capable node that should receive generated IPv4 packets.

### `settings`

- `source-ip4-range` `(string or array of strings)`
  Required IPv4 CIDR range or ordered list of IPv4 CIDR ranges, for example:
  - `"198.51.100.0/24"`
  - `["198.51.100.0/24", "203.0.113.0/24"]`

  `PacketSender` normalizes each subnet to its base address and generates one packet source address for every IPv4
  address in each subnet.

  When an array is provided, ranges are consumed in the array order: the first range is exhausted, then the second,
  then the third, and so on.

- `dest-ip4` `(string)`
  Required destination IPv4 address.

- `protocol-number` `(string)`
  Required protocol mode.

  Supported values:
  - `"TCP"`
  - `"UDP"`
  - `"ICMP"`
  - `"ALL"`

- `duration-ms` `(integer)`
  Required positive duration in milliseconds.

  `PacketSender` spreads the full generated packet set across this time window instead of bursting everything at once.

## Conditionally Required `settings`

- `dest-port` `(integer)`
  Required when `protocol-number` is `TCP`, `UDP`, or `ALL`.

  Expected range: `1` through `65535`.

- `src-port` `(integer or string)`
  Required when `protocol-number` is `TCP`, `UDP`, or `ALL`.

  Supported values:
  - a numeric port between `1` and `65535`
  - `"random"`

  `"random"` chooses a pseudo-random high ephemeral source port for each generated TCP or UDP packet.

## Detailed Behavior

### Startup and packet-store generation

During `onPrepare`, `PacketSender`:

- validates that the chain already has worker packet lines
- computes the full packet count from the source range and protocol mode
- allocates one contiguous local packet store
- materializes every packet into that store before any transmission starts
- partitions the global packet index range across workers

Transmission begins only later in `onStart`.

### Packet shapes

Every generated packet is IPv4 and uses a default TTL of `64`.

- `TCP`
  `PacketSender` generates minimal TCP segments with:
  - only the `ACK` flag set
  - valid IPv4 and TCP checksums
  - configured destination port
  - configured or pseudo-random source port

- `UDP`
  `PacketSender` generates minimal UDP datagrams with:
  - valid IPv4 and UDP checksums
  - configured destination port
  - configured or pseudo-random source port

- `ICMP`
  `PacketSender` generates ICMP echo requests with:
  - valid IPv4 and ICMP checksums
  - deterministic identifier and sequence fields

- `ALL`
  For every source IPv4 address in the configured range, `PacketSender` generates exactly `255` packets, one for each
  IPv4 protocol number from `0` through `254`.

  Special cases inside that set:
  - protocol `6` uses the valid TCP shape above
  - protocol `17` uses the valid UDP shape above
  - protocol `1` uses the valid ICMP shape above

  All other protocol numbers are emitted as valid IPv4 packets with a small opaque payload.

### Transmission timing

`PacketSender` assigns each generated packet a global deadline derived from:

- packet index inside the full generated set
- total packet count
- configured `duration-ms`

Workers then send their assigned ranges according to those deadlines. Packets that map to the same millisecond are sent
back-to-back on that worker. This keeps the total send window smooth without scheduling one timer per packet in
advance.

### Worker and packet-line behavior

`PacketSender` uses the chain's worker packet lines. It does not create or destroy normal per-connection lines.

Important consequences:

- no normal runtime `Finish` is emitted for packet lines
- unexpected downstream payload is dropped and recycled
- if a worker packet line dies during send, `PacketSender` treats that as a fatal runtime bug

### Memory behavior

The generated packet store is contiguous to avoid per-packet heap fragmentation.

For safety, `PacketSender` rejects configurations whose fully materialized packet store would exceed `512 MiB`. If you
need more traffic than that, split the workload across multiple `PacketSender` nodes or use a smaller source range per
node.

## Notes And Caveats

- `PacketSender` is IPv4-only.
- it is intentionally one-way and does not expose a downstream client-facing side
- `dest-port` and `src-port` are used only for generated TCP and UDP packets
- when `protocol-number` is `ALL`, the TCP and UDP packets inside the set still use those configured ports
- when `source-ip4-range` is an array, `PacketSender` walks the ranges in order and does not interleave them
- because it is a layer-3 chain head, worker packet-line init is supplied by Waterwall's normal packet-chain bootstrap
