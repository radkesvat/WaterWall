# FakeTcpHeader Node

`FakeTcpHeader` carries a complete IPv4 packet inside an outer IPv4 packet with
a configurable TCP-shaped header. It adds no TCP connection or handshake. The
original IPv4 header, transport header, addresses, ports, options and payload
remain inside the carrier and are restored on receive.

```text
outer IPv4 header | fake TCP header and options | complete original IPv4 packet
```

This is a Layer-3 packet transform. Enter from `TunDevice`, or use
`ConnectionToPackets` to turn normal UDP application lines into inner packets.
Use `PacketsToConnection` to expose received inner TCP/UDP flows to normal
connectors. Do not connect this node directly to a UDP listener or connector.

## Configuration

```json
{
  "name": "fake-tcp-header",
  "type": "FakeTcpHeader",
  "settings": {
    "role": "client",
    "local-ipv4": "192.0.2.10",
    "peer-ipv4": "198.51.100.10",
    "local-port": 40001,
    "peer-port": 40000,
    "protocol-number": 6,
    "mtu": 1500,
    "sequence": 12345,
    "acknowledgment": 67890,
    "window": 65535,
    "urgent-pointer": 0,
    "options": "01010101"
  },
  "next": "tcp-flags"
}
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `local-ipv4` | Required | Non-loopback IPv4 unicast address used as the outer source on send and required outer destination on receive. Use an address assigned to this host. |
| `peer-ipv4` | Required | Non-loopback IPv4 unicast address used as the outer destination on send and required outer source on receive. |
| `local-port` | `40000` | Outer TCP source port on send and required destination port on receive; integer `1..65535`. |
| `peer-port` | `40000` | Outer TCP destination port on send and required source port on receive; integer `1..65535`. |
| `role` | `"client"` | `client` encodes upstream and decodes downstream. `server` decodes upstream and encodes downstream. |
| `protocol-number` | `6` | Literal outer IPv4 protocol byte, integer `0..255`. Set `6` for TCP. Other numbers still carry the same TCP-shaped bytes, with a pseudoheader checksum using that number. |
| `mtu` | `1500` | Maximum complete carrier packet length, including outer headers; integer from `68 + 40 + options bytes` through `1500`. |
| `sequence` | `0` | TCP sequence field, integer `0..4294967295`, constant for every outgoing carrier. |
| `acknowledgment` | `0` | TCP acknowledgment field, same range and constant behavior. |
| `window` | `65535` | TCP window field, integer `0..65535`. |
| `urgent-pointer` | `0` | TCP urgent pointer, integer `0..65535`. |
| `options` | `""` | Raw hexadecimal TCP option bytes, `0..40` bytes in four-byte groups. Include EOL/NOP padding yourself; contents are emitted verbatim and data offset is calculated automatically. |

Both addresses are required. Optional defaults apply only to omitted fields.
Explicit nulls, wrong types, fractional or out-of-range numbers, unknown keys,
and malformed option strings fail creation. Wildcard, `0/8`, loopback,
multicast and reserved high IPv4 addresses are rejected for carrier addresses.

Reverse the local/peer addresses and ports on the other endpoint. Both peers
must agree on the protocol number. Receive uses the packet's data offset and
accepts differing outgoing TCP options and other header-template fields, within
the receiver's configured carrier MTU.

The outer IPv4 header is 20 bytes, uses TTL 64, sets DF, and copies the inner
packet's type-of-service byte. Outer lengths and IPv4/TCP-shaped checksums are
generated automatically. Carrier ports are independent of every inner flow's
ports.

## TCP flags

TCP flags start at zero. Reuse **IpManipulator**, which implements all eight
flag setters:

```json
{
  "name": "tcp-flags",
  "type": "IpManipulator",
  "settings": {
    "mtu": 1500,
    "up-tcp-bit-ack": "on",
    "up-tcp-bit-psh": "on"
  },
  "next": "raw"
}
```

Keep this node on the carrier side. For a server, put it before
`FakeTcpHeader` and use `dw-tcp-bit-*` for outgoing replies. Use protocol 6:
the flag editor recognizes native TCP packets. Leave `preserve-tcp-bitflags`
disabled; an appended flags trailer would become trailing bytes after the inner
IPv4 packet and fail exact inner-length validation.

Set `IpManipulator.mtu` explicitly to the carrier MTU. Inheriting the smaller
inner/core MTU can make its normal TCP segmentation split a carrier into pieces
that no longer contain a complete inner packet.

## UDP listener client and server

```text
client: UdpListener -> ConnectionToPackets -> FakeTcpHeader(role=client)
                   -> IpManipulator(up-tcp-bit-*) -> RawSocket

server: RawSocket -> IpManipulator(dw-tcp-bit-*) -> FakeTcpHeader(role=server)
                 -> PacketsToConnection -> UdpConnector -> UDP destination
```

Requests travel upstream in both chains; replies travel downstream.
`ConnectionToPackets` may use private inner addresses such as `10.90.0.1` and
`10.90.0.2`; these need not be the carrier addresses. Its source and destination
tuple remains inside the carrier. The server's `UdpConnector` can override the
destination address and port, while `PacketsToConnection` retains the original
inner tuple for replies.

## TUN client

```text
client: TunDevice -> FakeTcpHeader(role=client)
                 -> IpManipulator(up-tcp-bit-*) -> RawSocket
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

Configurations are provided in [examples/client](examples/client/config.json),
[examples/client-tun](examples/client-tun/config.json) and
[examples/server](examples/server/config.json). Replace the example carrier
addresses with assigned host addresses. Run Waterwall from the selected
directory using its `core.json`. The listener client accepts UDP on
`127.0.0.1:5000`; the server forwards to UDP `127.0.0.1:5300`.
The TUN example assigns `10.90.0.1/24`; send UDP to `10.90.0.2:5300`
through its connected route. Keep `10.90.0.2` unassigned on the client so
the kernel sends those packets into TUN.

## Receive filtering

Reserve a carrier port pair and filter it on both RawSocket endpoints. For the
client address and ports in the configuration above:

```json
{
  "name": "raw",
  "type": "RawSocket",
  "settings": {
    "capture-filter-mode": "source-ip",
    "capture-ips": ["198.51.100.10"],
    "capture-protocols": [6],
    "capture-tcp-source-port": 40000,
    "capture-tcp-dest-port": 40001,
    "fragment-policy": "preserve-fragments"
  }
}
```

On the server, capture source `192.0.2.10`, TCP source port `40001` and TCP
destination port `40000`. Place its RawSocket at the beginning of the chain.
The port predicates imply TCP and exclude fragmented carriers before capture;
the node also checks the configured outer addresses and ports during decode.

Linux uses fixed-size cBPF before both NFQUEUE and incoming NOTRACK processing;
Windows uses WinDivert TCP field predicates. Unrelated TCP ports and UDP from
the same peer remain in the host stack. Reserve these exact carrier ports so
ordinary applications do not use the same peer tuple. Tuple filtering provides
no authentication.

## MTU and validation

The limits count the complete inner and outer IP packets:

```text
outer overhead = 20-byte IPv4 + 20-byte TCP + configured TCP options
inner MTU      = carrier MTU - outer overhead
UDP payload    = inner MTU - inner IPv4 header - 8-byte UDP header
```

At carrier MTU 1500, no TCP options gives inner MTU **1460** and maximum UDP
application payload **1432 bytes** with a 20-byte inner IPv4 header. Four TCP
option bytes give inner MTU **1456** and UDP payload **1428 bytes**. Subtract
any inner IPv4 option bytes too.

Set core `misc.mtu`, `ConnectionToPackets.mtu` or `TunDevice.device-mtu` to the
appropriate inner MTU, and set `FakeTcpHeader.mtu` and carrier-side
`IpManipulator.mtu` to the carrier MTU. Configure both ends consistently for
traffic in both directions. Keep UDP datagrams within the inner MTU when the
receiver uses `PacketsToConnection`; bridge-generated fragments cannot enter
that stack consumer. A lower path MTU requires smaller configured limits.

- IPv4 only. Each input must contain exactly one complete IPv4 packet.
  Malformed lengths, truncated TCP/UDP headers and invalid checksums are dropped.
  IPv4 UDP checksum zero remains valid.
- Inner TCP/UDP packets, their headers and IPv4 options are preserved. Inner
  IPv4 fragments are carried individually and can be delivered to a receiving
  TUN for kernel reassembly. The transform itself performs no reassembly;
  `PacketsToConnection` rejects inner fragments.
- Encoding honors a pending internal checksum-repair request before wrapping.
  Decode checks the inner packet independently of any outer checksum-repair
  request. Successful conversion clears the request.
- Outer fragments, incorrect peer addresses/ports/protocol, oversized carriers
  and inputs larger than the configured inner MTU are dropped. Encoding requires
  available prepend capacity. There is no automatic fragmentation or carrier
  segmentation.
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

Build option: `INCLUDE_FAKE_TCP_HEADER` (enabled by default).
