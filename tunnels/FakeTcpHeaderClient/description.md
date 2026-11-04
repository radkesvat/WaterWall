# FakeTcpHeaderClient Node

`FakeTcpHeaderClient` adds an extra TCP-looking header to an existing IPv4
packet. Its peer, [FakeTcpHeaderServer](../FakeTcpHeaderServer/description.md),
removes that header to recover the original TCP or UDP traffic. Replies take
the reverse path: the server adds the fake header and the client removes it.
The existing IPv4 header is reused, so there is exactly one IPv4 header.

In this page, **native** means the original packet or its original TCP/UDP
header. A **carrier** is the packet after the fake TCP header has been added.
Encoding adds the fake header; decoding removes it.

The fake TCP layer does not establish a TCP connection, track sequence numbers,
or retransmit lost packets. Each packet uses the configured fake TCP template
independently. Original TCP traffic still has its own real TCP behavior, as
explained below; original UDP traffic does not gain TCP reliability.

The node only transforms packets. It does not select IP addresses or remember
the original ones. Chain configuration, including `IpOverrider`, supplies public
addresses and restores the addresses expected by the receiving stack.

| Event | Action |
| --- | --- |
| upstream native IPv4 packet | Insert fake TCP from `client-port + i` to `server-port`, then forward upstream. |
| downstream carrier | Validate and remove fake TCP, then forward the native packet downstream. |
| refused packet | Recycle it on its worker and emit a rate-limited diagnostic. |

## What `payload-protocol` Means

`payload-protocol` tells the node **what kind of packet it receives before
adding the fake TCP header**. It also tells the receiving peer which protocol
to restore after removing that header.

| Setting on both peers | Original traffic entering the encoder |
| --- | --- |
| `"payload-protocol": 6` | IPv4 TCP packets |
| `"payload-protocol": 17` | IPv4 UDP packets |

The numbers 6 and 17 are IPv4 protocol numbers, not port numbers. The setting
does not select an application protocol such as HTTP or DNS. It also does not
choose the fake header's protocol: the encoder produces an IPv4/TCP carrier in
both modes. An `IpManipulator` node using ProtoSwap can change that carrier
protocol later; see [Composition](#composition).

### UDP example: `payload-protocol: 17`

```text
Before encoding:
[IPv4 says UDP][original UDP header][data]

Between the FakeTcpHeader peers:
[IPv4 says TCP][fake TCP header][original UDP header][data]

After decoding:
[IPv4 says UDP][original UDP header][data]
```

The receiver removes the fake TCP header and sets the IPv4 protocol back to
UDP because both peers were configured with 17. The original UDP header and
application data remain; this is still UDP traffic, with no added delivery or
ordering guarantee.

### TCP example: `payload-protocol: 6`

```text
Before encoding:
[IPv4 says TCP][original TCP header][data]

Between the FakeTcpHeader peers:
[IPv4 says TCP][fake TCP header][original TCP header][data]

After decoding:
[IPv4 says TCP][original TCP header][data]
```

There are **two TCP headers while encoded**, but only one IPv4 header. The
receiver removes only the fake TCP header. The original TCP header, including
its options, sequence numbers, acknowledgments and flags, is retained. Its
checksum is adjusted as described in [Native Checksum Representation](#native-checksum-representation).

The original TCP endpoints still perform their real handshake and
retransmissions. For example, an original SYN packet is carried behind the fake
ACK|PSH header; after decoding, the original SYN reaches the receiving TCP stack.
The node's `sequence`, `acknowledgment`, `window`, and `options` settings control
only the fake header. They do not replace the real TCP connection's fields.

### Why both peers need the setting

The visible IPv4 protocol is TCP while encoded, and the packet contains no
extra field identifying its original protocol. The receiver uses its configured
`payload-protocol`; it does not discover the original protocol automatically.
Both peers must therefore use the same value. A mismatch can cause a drop or
incorrect interpretation, and cannot always be detected from packet structure.

Each configured pair accepts **one original protocol**. Encoding drops a packet
whose protocol does not match the setting. This matters with TUN: a TUN can
produce TCP, UDP, ICMP and other packets. Setting 6 accepts its TCP packets;
setting 17 accepts its UDP packets. Carrying both requires separate appropriately
routed pairs; changing this setting does not convert one protocol into another.

## Chain Order

```text
client: UdpListener -> ConnectionToPackets -> FakeTcpHeaderClient -> IpOverrider -> RawSocket
        TunDevice   -> FakeTcpHeaderClient -> IpOverrider -> RawSocket

server: RawSocket -> IpOverrider -> FakeTcpHeaderServer -> PacketsToConnection -> UdpConnector
        RawSocket -> IpOverrider -> FakeTcpHeaderServer -> TunDevice
```

Requests travel upstream in both chains and replies downstream. Both neighbours
must be Layer-3 packet nodes. Use `ConnectionToPackets` to turn ordinary
connections into native packets; do not connect this node directly to a UDP
listener or connector.

The listener/connector chains shown above carry UDP and use `payload-protocol:
17`. For native TCP, use TCP listeners/connectors with the packet bridges and
set both FakeTcpHeader nodes to 6. `ConnectionToPackets` (CTP) and
`PacketsToConnection` (PTC) are the packet bridges referred to below. In either
case, upstream means toward the next node; downstream means toward the previous
node. Client/server names do not reverse these directions.

## Configuration Example

```json
{
  "name": "fake-tcp-header",
  "type": "FakeTcpHeaderClient",
  "settings": {
    "payload-protocol": 17,
    "server-port": 40000,
    "client-port": 40001,
    "client-port-count": 16,
    "sequence": 12345,
    "acknowledgment": 67890,
    "window": 65535,
    "urgent-pointer": 0,
    "options": "01010101"
  },
  "next": "carrier-addresses"
}
```

Both nodes accept the same keys. `settings` and its integer `payload-protocol`
are required; the other keys have defaults.

| Setting | Default | Meaning |
| --- | --- | --- |
| `payload-protocol` | **required** | Original packet's transport: integer `6` for TCP or `17` for UDP. Both peers must agree; see the examples above. |
| `server-port` | `40000` | Fake TCP server port. Integer `1..65535`. |
| `client-port` | `40001` | First fake TCP client port. Integer `1..65535`. |
| `client-port-count` | `16` | Client port count, integer `1..1024`. The range must end at or below `65535`, and `server-port` must be outside it. |
| `sequence` | `0` | Sequence number of every outgoing fake header. Integer `0..4294967295`. |
| `acknowledgment` | `0` | Acknowledgment number of every outgoing fake header. Integer `0..4294967295`. |
| `window` | `65535` | Fake TCP window. Integer `0..65535`. |
| `urgent-pointer` | `0` | Fake TCP urgent pointer. Integer `0..65535`. |
| `options` | `""` | Hexadecimal fake TCP options, `0..40` bytes in multiples of 4, emitted verbatim. Include any NOP/EOL padding. |

Missing `settings`, `{}` or a missing, null, non-integer or unsupported
`payload-protocol` fails creation with a diagnostic naming
`FakeTcpHeaderClient->settings->payload-protocol`. Unknown keys, wrong types,
fractions and out-of-range template values also fail creation, naming the key.
A non-object `settings` is invalid. Invalid hexadecimal options, odd hex length,
lengths not divisible by four bytes, and lengths above 40 bytes are refused.
There are no address, MTU, flag or alternative carrier-protocol settings here.

Both peers must agree on `payload-protocol`, `server-port`, `client-port` and
`client-port-count`. Their sequence, acknowledgment, window, urgent pointer and
options may differ. Receive reads the incoming data offset and does not compare
these template fields or flags. There is no native-protocol tag on the wire:
structural checks cannot guarantee detection of a protocol disagreement.

All port and TCP-template settings in this table describe the **fake header**.
For example, native UDP traffic for port 5300 can use fake TCP destination port
40000 on the network. The original UDP port remains in the original UDP header;
setting `server-port` does not change the application's destination port.

## Wire Rules

For UDP (`payload-protocol: 17`):

```text
native:  [existing IPv4, protocol 17][original UDP header][application bytes]
carrier: [same IPv4, protocol 6][fake TCP + options][original UDP header][application bytes]
decoded: [same IPv4, protocol 17][original UDP header][application bytes]
```

For TCP (`payload-protocol: 6`), the original TCP header, its options and its
payload follow fake TCP. Both native and encoded packets have IP protocol 6;
callback direction selects encode or decode, never the visible protocol alone.

IPv4 IHL is the length of the existing IPv4 header, including any IPv4 options.
That actual length locates fake TCP. The transform preserves
source/destination, IHL/options, identification, DF, TTL and DSCP/ECN. It changes
protocol and total length and recomputes the IPv4 checksum over the actual IHL.
Transit TTL or ECN changes remain visible after decoding. There is no protected
inner IPv4 header and no saved address to recover.

Fake TCP uses the configured ports and template, flags ACK|PSH (`0x18`), and a
valid checksum over its complete segment and a protocol-6 pseudo-header with
the packet's current addresses. Receive verifies the IPv4 and fake TCP
checksums unless an internal checksum-repair request is pending. Addresses are
not compared with a local template; configure RawSocket capture filtering.

## Native Checksum Representation

TCP and UDP checksums include the IP addresses in their calculation. If
`IpOverrider` changes those addresses while the original transport header is
behind fake TCP, its original checksum needs a corresponding adjustment. The
codec handles this by temporarily removing the addresses' contribution from
the native checksum and adding the current addresses' contribution on decode.
**It does not set the packet's IP address fields to zero.** The zero addresses
below describe only the checksum calculation.

Before insertion, encode incrementally changes the native TCP/UDP checksum's
address contribution from the current addresses to zero/zero. Its native
protocol and transport-length contribution remain. Decode restores the
contribution of the addresses currently in the surviving IPv4 header. Thus
`IpOverrider` can rewrite an encoded packet using only its visible fake TCP
header, and native checksums decode consistently with the final addresses.
Ordinary rewrites before encode or after decode operate on native TCP/UDP.

Without a native repair request, this adjustment preserves invalid native
checksum residuals. Disabled UDP checksum zero remains zero; enabled UDP
arithmetic zero is `0xffff`, and TCP zero is an ordinary checksum value. UDP
uses its declared datagram length, including when permitted IP payload padding
follows it. Intentionally invalid IPv4 header checksums are not preserved.

A pending native checksum request is completed before normalization; refused
repair drops the packet unchanged. On decode a request makes the visible
IPv4/fake TCP checksums non-authoritative but does not waive framing, port,
fragment or size checks. It applies only to that visible layer and does not
repair corruption in hidden native bytes. Successful encode/decode clears the
consumed request. Arbitrary hidden transport or payload edits while encoded
require a transform that understands this representation.

## Per-Flow Carrier Ports

Each native packet selects a client carrier port before insertion:

```text
i = deviceFlowWorkerHash(native packet) % client-port-count

client -> server: source client-port + i, destination server-port
server -> client: source server-port,     destination client-port + i
```

The fallback index is zero when hashing is unavailable. Supported native flows
hash their addresses, native protocol and ports. The hash is endpoint-symmetric:
request and reply select the same index when their tuples at the two encoders
are reverses. Arbitrary address rewrites can change that relationship. A stable
native tuple in each direction still gives stable receive distribution.

RawSocket hashes the visible addresses and fake TCP ports. `multi-queue` uses
kernel receive distribution; a single queue uses software worker selection.
Decode checks the server port and configured client range, rather than
recomputing an expected native-flow index.

## Receive Filtering

On the client, capture the server's public IPv4 and fake TCP source port:

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

The server uses the client's public IPv4 and `capture-tcp-dest-port: 40000`.
Decode rejects client ports outside the configured range. Reserve `server-port`
between these hosts: genuine TCP using that server-side port is captured and
dropped. Keep it out of the server's ephemeral port range, for example through
`net.ipv4.ip_local_reserved_ports`. Tuple filtering provides no authentication.

## Composition

Because there is only one IPv4 header, an address rewrite changes the same
address fields that will remain after decoding. The node cannot recover private
addresses that were replaced with public ones. Configure their restoration when
the receiving TUN or connection stack expects the original addresses.

This client-side `IpOverrider`, between the codec and RawSocket, sets public
addresses on send and restores the native tuple on receive **before decode**:

```json
{
  "name": "carrier-addresses",
  "type": "IpOverrider",
  "settings": {
    "up": {
      "source-ip": { "ipv4": "192.0.2.10" },
      "dest-ip": { "ipv4": "198.51.100.10" }
    },
    "down": {
      "source-ip": { "ipv4": "10.90.0.2" },
      "dest-ip": { "ipv4": "10.90.0.1" }
    }
  },
  "next": "raw"
}
```

The server's corresponding instance restores `10.90.0.1 -> 10.90.0.2` upstream
and sets `198.51.100.10 -> 192.0.2.10` downstream. Restoration is a chain choice;
it is necessary wherever a TUN or connection stack expects those private
addresses. The codec never remembers them. Other rewrite placements are valid
when they preserve checksums and routing.

To change fake TCP flags, place `IpManipulator` between the codec and RawSocket,
using `up-tcp-bit-*` on the client and `dw-tcp-bit-*` on the server. To carry
fake TCP under another IP protocol, place `IpManipulator` with `protoswap-tcp`
next to each codec and capture that protocol without TCP port qualifiers, for
example `"capture-protocols": [253]`. ProtoSwap must restore protocol 6 before
fake TCP decoding. RawSocket's default `opaque-flow-mode: "prefix"` steers that
opaque protocol using the first four payload bytes, the fake TCP ports.

## MTU and Validation

With `H` the existing IPv4 IHL (`20..60`) and `F = 20 + options length`:

```text
native length    = H + native transport bytes
encoded length   = native length + F
maximum native IP packet length = 1500 - outgoing F
```

| Fake TCP options | Overhead | Maximum native IP packet | UDP application bytes with 20-byte IPv4 |
| --- | --- | --- | --- |
| 0 bytes | 20 bytes | 1480 bytes | 1452 bytes |
| 4 bytes | 24 bytes | 1476 bytes | 1448 bytes |
| 40 bytes | 60 bytes | 1440 bytes | 1412 bytes |

These native MTUs count the **whole original IPv4 packet**, including its IP and
TCP/UDP headers. For example, without fake TCP options, a 1480-byte native packet
becomes a 1500-byte carrier. With a 20-byte IPv4 header and an 8-byte UDP header,
that leaves 1452 bytes for the application's UDP data. IPv4 options consume
space inside the native packet, while fake TCP options increase the added
overhead.

Set `TunDevice.device-mtu`, `ConnectionToPackets.mtu` and
`PacketsToConnection.mtu` (otherwise inherited from core `misc.mtu`) to fit
the largest outgoing fake header used by either peer. A lower path MTU requires
smaller values. The codec neither fragments nor segments, discovers PMTU, or
adjusts native TCP MSS. It advertises 60 bytes of left padding; an encode needs
its outgoing `F` bytes and moves only the existing IPv4 header in place.

Both entry points require exactly one complete, unfragmented IPv4 datagram.
MF or a nonzero fragment offset is refused, including first and final fragments;
DF alone is preserved. Use upstream device reassembly (`fragment-policy:
"reassemble"`, the default) for fragmented input. A carrier fragmented in transit
must likewise be reassembled before decode. `preserve-fragments` cannot make
fragments acceptable to this codec. CTP-emitted UDP fragments also require
reassembly before encoding, so keep application datagrams within the native MTU.

Encode requires the configured native protocol and valid native TCP/UDP header
geometry. Decode requires protocol 6, valid fake TCP geometry and ports, then
valid geometry for the configured native transport after fake TCP. IPv4 total
length must equal the buffer length; malformed headers, IPv6, trailing buffer
bytes, oversized carriers and insufficient headroom are dropped. UDP length
must be at least eight bytes and fit its IP-bounded native span; TCP data offset
must cover a complete header and fit that span.

Every refusal preserves buffer bytes, headroom, cursor, length and checksum
intent before the node recycles it. Drop diagnostics name the reason and use
the network logger at `ERROR`. Outgoing diagnostics include packet size, maximum
native size, overhead and headroom; incoming diagnostics include packet size
and maximum carrier size. At most one diagnostic per node is emitted every five
seconds, shared by both directions, all reasons and all workers.

## Limits and Detectability

- The fixed fake TCP template, lack of handshake and extra native transport header
  are easy to fingerprint. Stateful firewalls, NAT and middleboxes may drop it.
- NAT rewriting fake TCP ports breaks the configured mapping.
- There is no authentication or encryption. Traffic remains visible and anyone
  able to send matching captured tuples can inject packets. Use appropriate
  protection inside the native traffic.
- The fake TCP layer adds no ordering, loss recovery or reliability. UDP retains
  its native loss/reordering behavior; native TCP retains its own TCP behavior.

## Examples

- [examples/client](examples/client/config.json): UDP on `127.0.0.1:5000`,
  through CTP from `10.90.0.1` to `10.90.0.2:5300`.
- [examples/client-tun](examples/client-tun/config.json): TUN at
  `10.90.0.1/24`; send UDP to unassigned `10.90.0.2:5300` so it routes into TUN.
- [server example](../FakeTcpHeaderServer/examples/server/config.json): the
  peer for both examples, forwarding to UDP `127.0.0.1:5300`.

All examples select `payload-protocol: 17`, restore private addresses explicitly
and use native MTU 1480 without fake TCP options. Replace documentation public
addresses `192.0.2.10` and `198.51.100.10` in RawSocket and IpOverrider. Run from
the example directory with its `core.json`. The TUN example's `route-table:
"off"` leaves route selection to you: keep the public server reachable through
the ordinary interface so carriers cannot loop into TUN. To carry native TCP,
configure both nodes with integer `payload-protocol: 6` and appropriate TCP edges.

## Node Metadata

| Property | Value |
| --- | --- |
| `version` | `1` |
| node flags | `kNodeFlagNone` |
| `can_have_prev`, `can_have_next` | `true` |
| node and neighbour layers | `kNodeLayer3` |
| `required_padding_left` | `60` bytes |
| line state | none |

Build option: `INCLUDE_FAKE_TCP_HEADER_CLIENT` (default `TRUE`). Both nodes use
`FakeTcpHeaderCommon` and `ww`; neither requires the peer node or IpManipulator
module to build.

The implementation is a pure packet tunnel created with `packettunnelCreate()`.
It keeps no per-line connection state.
