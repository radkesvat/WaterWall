# FakeTcpHeaderServer Node

`FakeTcpHeaderServer` is the receiving end of
[FakeTcpHeaderClient](../FakeTcpHeaderClient/description.md). It removes the
outer IPv4 header and the configurable TCP-shaped header from each carrier and
restores the complete original IPv4 packet, and it wraps reply packets in
carriers toward the client. It adds no TCP connection or handshake.

```text
outer IPv4 header | fake TCP header and options | complete original IPv4 packet
```

This is a Layer-3 packet transform. Upstream it decodes carriers from the
client; downstream it encodes reply packets into carriers. Use
`PacketsToConnection` to expose received inner TCP/UDP flows to normal
connectors, or `TunDevice` to deliver them to the kernel. Do not connect this
node directly to a UDP listener or connector.

```json
{
  "name": "fake-tcp-header",
  "type": "FakeTcpHeaderServer",
  "settings": {
    "server-port": 40000,
    "client-port": 40001,
    "client-port-count": 16
  },
  "next": "flows"
}
```

## Settings

Both nodes of a pair accept the same keys. The `settings` object is optional.

```json
{
  "server-port": 40000,
  "client-port": 40001,
  "client-port-count": 16,
  "sequence": 12345,
  "acknowledgment": 67890,
  "window": 65535,
  "urgent-pointer": 0,
  "options": "01010101"
}
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `server-port` | `40000` | Carrier TCP port of the server side; integer `1..65535`. |
| `client-port` | `40001` | First carrier TCP port of the client side; integer `1..65535`. |
| `client-port-count` | `16` | Number of client carrier ports, integer `1..1024`. `client-port + client-port-count - 1` must not exceed `65535`, and `server-port` must lie outside the client range. |
| `sequence` | `0` | TCP sequence field, integer `0..4294967295`, constant for every outgoing carrier. |
| `acknowledgment` | `0` | TCP acknowledgment field, same range and constant behavior. |
| `window` | `65535` | TCP window field, integer `0..65535`. |
| `urgent-pointer` | `0` | TCP urgent pointer, integer `0..65535`. |
| `options` | `""` | Raw hexadecimal TCP option bytes, `0..40` bytes in four-byte groups. Include EOL/NOP padding yourself; contents are emitted verbatim and data offset is calculated automatically. |

Explicit nulls, wrong types, fractional or out-of-range numbers, unknown keys
and malformed option strings fail creation. Both peers must use the same
`server-port`, `client-port` and `client-port-count`. Receive uses the packet's
data offset and accepts differing outgoing TCP options and other header-template
fields.

## Carrier header

The outer IPv4 header is 20 bytes, uses TTL 64, ID 0 and DF, protocol 6, and
copies the inner packet's DSCP bits; the ECN field is always Not-ECT. The outer
source and destination addresses are the inner packet's addresses; place an
`IpOverrider` next to the node to set the public carrier addresses. TCP flags
are ACK + PSH. Outer lengths and IPv4/TCP checksums are generated
automatically.

Each inner flow selects one client carrier port from its flow hash, so the
carriers of different flows spread across receive queues. A request and its
reply select the same port. The client sends from `client-port + i` to
`server-port`; the server replies from `server-port` to `client-port + i`.
Decode checks only the ports; it does not check the outer addresses.

To use another outer protocol number, add `IpManipulator` `protoswap-tcp` next
to the carrier node. To emit other TCP flags, use `IpManipulator`
`up-tcp-bit-*` / `dw-tcp-bit-*`.

## UDP listener client and server

```text
client: UdpListener -> ConnectionToPackets -> FakeTcpHeaderClient
                   -> IpOverrider -> RawSocket

server: RawSocket -> IpOverrider -> FakeTcpHeaderServer
                 -> PacketsToConnection -> UdpConnector -> UDP destination
```

Requests travel upstream in both chains; replies travel downstream. The client
`IpOverrider` sets `up.source-ip` to the client public IPv4 and `up.dest-ip` to
the server public IPv4. The server `IpOverrider` sets `down.source-ip` to the
server public IPv4 and `down.dest-ip` to the client public IPv4.
`ConnectionToPackets` may use private inner addresses such as `10.90.0.1` and
`10.90.0.2`; these need not be the carrier addresses. Its source and destination
tuple remains inside the carrier. The server's `UdpConnector` can override the
destination address and port, while `PacketsToConnection` retains the original
inner tuple for replies.

## TUN client

```text
client: TunDevice -> FakeTcpHeaderClient -> IpOverrider -> RawSocket
```

Kernel UDP traffic routed into TUN becomes the inner IPv4 packet. Return
decoding restores that packet toward TUN, including the original inner source
and destination addresses and ports. This preserves the application's tuple
without a `ConnectionToPackets` node.

Set `TunDevice.device-mtu` to the inner MTU and route the intended inner
destination range through TUN. Keep the outer peer address reachable through
the ordinary network interface so carrier output cannot loop back into TUN.
For explicit routes, `route-table: "off"` leaves route selection to the user.
The server chain above works for inner UDP traffic; `PacketsToConnection`
requires complete, unfragmented inner packets.

Configurations are provided in
[FakeTcpHeaderClient examples/client](../FakeTcpHeaderClient/examples/client/config.json),
[FakeTcpHeaderClient examples/client-tun](../FakeTcpHeaderClient/examples/client-tun/config.json) and
[FakeTcpHeaderServer examples/server](../FakeTcpHeaderServer/examples/server/config.json).
Replace the example carrier addresses with assigned host addresses. Run
Waterwall from the selected directory using its `core.json`. The listener
client accepts UDP on `127.0.0.1:5000`; the server forwards to UDP
`127.0.0.1:5300`. The TUN example assigns `10.90.0.1/24`; send UDP to
`10.90.0.2:5300` through its connected route. Keep `10.90.0.2` unassigned on
the client so the kernel sends those packets into TUN.

## Receive filtering

Filter the carriers on both RawSocket endpoints. On the client:

```json
{
  "name": "raw",
  "type": "RawSocket",
  "settings": {
    "capture-filter-mode": "source-ip",
    "capture-ips": ["198.51.100.10"],
    "capture-protocols": [6],
    "capture-tcp-source-port": 40000
  }
}
```

On the server, capture source `192.0.2.10` with `capture-protocols: [6]` and
TCP destination port `40000`. Place its RawSocket at the beginning of the
chain. Reserve the server port so ordinary applications do not use it with the
same peer. Tuple filtering provides no authentication.

## MTU and validation

The limits count the complete inner and outer IP packets:

```text
outer overhead = 20-byte IPv4 + 20-byte TCP + configured TCP options
inner MTU      = 1500 - outer overhead
UDP payload    = inner MTU - inner IPv4 header - 8-byte UDP header
```

The carrier is at most 1500 bytes. No TCP options gives inner MTU **1460** and
maximum UDP application payload **1432 bytes** with a 20-byte inner IPv4
header. Four TCP option bytes give inner MTU **1456** and UDP payload
**1428 bytes**. Subtract any inner IPv4 option bytes too.

Set core `misc.mtu`, `ConnectionToPackets.mtu` or `TunDevice.device-mtu` to the
appropriate inner MTU. Configure both ends consistently for traffic in both
directions. Keep UDP datagrams within the inner MTU when the receiver uses
`PacketsToConnection`. A lower path MTU requires smaller configured limits.

- IPv4 only. Each input must contain exactly one complete IPv4 packet.
  Inner packets are checked for framing only; their checksums are carried
  unchanged, including intentionally invalid ones.
- Encoding honors a pending internal checksum-repair request before wrapping.
  Decode skips outer checksum verification when a repair is requested and
  otherwise requires valid outer IPv4 and TCP checksums. Successful conversion
  clears the request.
- Outer fragments, carrier ports outside the mapping, oversized carriers and
  inputs larger than the inner MTU are dropped. Encoding requires available
  prepend capacity. There is no automatic fragmentation or carrier
  segmentation. Drops are logged per reason, at most once every 5 seconds.
- No TCP handshake, sequence tracking, retransmission, congestion control,
  encryption or authentication is added. UDP retains its loss/reordering
  behavior. Networks enforcing real TCP state may refuse the carrier.

## Lifetime and node metadata

Packet lines remain chain-owned. The node has zero line state, retains no
buffers, forwards callbacks in their original direction and transfers each
forwarded buffer once. It never calls `lineDestroy()`.

Prepending/removing outer headers leaves inner packet bytes in place, except
when an explicit checksum-repair request requires checksum updates. The maximum
advertised left padding is 80 bytes.

| Property | Value |
| --- | --- |
| Node flags | `kNodeFlagNone` |
| `can_have_prev` / `can_have_next` | `true` / `true` |
| Layer and both neighbor layers | `kNodeLayer3` |
| `required_padding_left` | `80` bytes |

Build option: `INCLUDE_FAKE_TCP_HEADER_SERVER` (enabled by default).
