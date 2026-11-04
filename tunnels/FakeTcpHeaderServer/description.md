# FakeTcpHeaderServer Node

`FakeTcpHeaderServer` receives packets with an extra TCP-looking header from
[FakeTcpHeaderClient](../FakeTcpHeaderClient/description.md). It removes that
header to recover the original TCP or UDP traffic. For replies, it adds the fake
header again so the client can remove it. The existing IPv4 header is reused;
there is exactly one IPv4 header.

In this page, **native** means the original packet or its original TCP/UDP
header. A **carrier** is the packet after the fake TCP header has been added.
Encoding adds the fake header; decoding removes it.

The fake TCP layer does not establish a connection, track a TCP session, or
retransmit lost packets. Original TCP traffic still has its own real handshake
and reliability; original UDP traffic does not gain those features. The node
only transforms packets. Chain configuration determines addresses and restores
the addresses expected by the receiving TUN or connection stack.

| Event | Action |
| --- | --- |
| upstream carrier | Validate and remove fake TCP, restore the configured native protocol and forward upstream. |
| downstream native IPv4 packet | Insert fake TCP from `server-port` to `client-port + i`, then forward downstream. |
| refused packet | Recycle it on its worker and emit a rate-limited diagnostic. |

## What `payload-protocol` Means

`payload-protocol` identifies **the original traffic behind the fake TCP
header**. The server uses it when decoding incoming packets and when encoding
native reply packets. It must match the client's setting.

| Setting on both peers | Original traffic |
| --- | --- |
| `"payload-protocol": 6` | IPv4 TCP packets |
| `"payload-protocol": 17` | IPv4 UDP packets |

These are IPv4 protocol numbers, not ports or application protocols such as
HTTP or DNS. In both modes, FakeTcpHeader itself produces an IPv4/TCP carrier.
The setting tells it what to restore after removing fake TCP, not which
protocol to advertise in IPv4 while encoded. An `IpManipulator` node using
ProtoSwap can change the visible carrier protocol later; see [Composition](#composition).

### UDP example: `payload-protocol: 17`

```text
Original packet before encoding at the client:
[IPv4 says UDP][original UDP header][data]

Packet received from the client:
[IPv4 says TCP][fake TCP header][original UDP header][data]

Packet after server decoding:
[IPv4 says UDP][original UDP header][data]
```

The server removes fake TCP and sets the IPv4 protocol back to UDP because it
was configured with 17. The UDP header and application data remain. Replies
undergo the reverse operation at the server, then the client decodes them.
Adding this fake header does not give UDP delivery or ordering guarantees.

### TCP example: `payload-protocol: 6`

```text
Original packet before encoding at the client:
[IPv4 says TCP][original TCP header][data]

Packet received from the client:
[IPv4 says TCP][fake TCP header][original TCP header][data]

Packet after server decoding:
[IPv4 says TCP][original TCP header][data]
```

The encoded packet contains **two TCP headers and one IPv4 header**. The server
removes only the fake TCP header. The original TCP header keeps its options,
sequence numbers, acknowledgments and flags; its checksum is adjusted for the
current addresses as explained in [Wire Rules](#wire-rules).

The original TCP endpoints still perform their own handshake and
retransmissions. For example, an original SYN is carried behind a fake ACK|PSH
header and reaches the receiving stack as a SYN after decoding. The node's
configured `sequence`, `acknowledgment`, `window`, and `options` affect only the
fake header, not the real TCP connection.

### One original protocol per pair

The carrier has no extra field recording its original protocol. Both peers
must agree on `payload-protocol`; neither automatically detects whether the
hidden transport is TCP or UDP. A mismatch may cause drops or incorrect
interpretation and cannot always be detected by structural validation.

Each pair accepts one original protocol. Encoding drops replies that do not
match its configured protocol. A TUN can produce mixed TCP, UDP, ICMP and other
traffic, so one pair configured for TCP will not also carry its UDP packets.
Use separate appropriately routed pairs when both are needed. This setting
does not convert UDP into TCP or TCP into UDP.

## Chain Order

```text
server: RawSocket -> IpOverrider -> FakeTcpHeaderServer -> PacketsToConnection -> UdpConnector
        RawSocket -> IpOverrider -> FakeTcpHeaderServer -> TunDevice

client: UdpListener -> ConnectionToPackets -> FakeTcpHeaderClient -> IpOverrider -> RawSocket
        TunDevice   -> FakeTcpHeaderClient -> IpOverrider -> RawSocket
```

Requests travel upstream and replies downstream. `PacketsToConnection` converts
received native TCP/UDP flows into ordinary connection lines; `TunDevice`
delivers packets to the kernel. Both neighbours must be Layer-3 packet nodes.

The listener/connector examples above use UDP and `payload-protocol: 17`.
For native TCP, use TCP listeners/connectors with the packet bridges and set
both FakeTcpHeader nodes to 6. `ConnectionToPackets` (CTP) and
`PacketsToConnection` (PTC) are the bridges referred to below. Upstream means
toward the next node and downstream toward the previous node, on the server
as well as the client.

## Configuration Example

```json
{
  "name": "fake-tcp-header",
  "type": "FakeTcpHeaderServer",
  "settings": {
    "payload-protocol": 17,
    "server-port": 40000,
    "client-port": 40001,
    "client-port-count": 16,
    "sequence": 67890,
    "acknowledgment": 12345,
    "window": 65535
  },
  "next": "flows"
}
```

`settings` and integer `payload-protocol` are required. The setting is exactly
`6` for native TCP or `17` for native UDP, and must match the client. There is no
on-wire native-protocol identifier; malformed native structure can be rejected,
but automatic detection or guaranteed detection of disagreement is not provided.

| Setting | Default | Meaning |
| --- | --- | --- |
| `payload-protocol` | **required** | Original traffic: integer `6` for TCP or `17` for UDP. Must match the client; see the packet examples above. |
| `server-port` | `40000` | Fake TCP server port, integer `1..65535`. |
| `client-port` | `40001` | First fake TCP client port, integer `1..65535`. |
| `client-port-count` | `16` | Integer `1..1024`; client range must end at or below `65535` and exclude `server-port`. |
| `sequence` | `0` | Outgoing fake TCP sequence, integer `0..4294967295`. |
| `acknowledgment` | `0` | Outgoing fake TCP acknowledgment, integer `0..4294967295`. |
| `window` | `65535` | Fake TCP window, integer `0..65535`. |
| `urgent-pointer` | `0` | Fake TCP urgent pointer, integer `0..65535`. |
| `options` | `""` | Verbatim hexadecimal fake TCP options: `0..40` bytes, in four-byte groups. |

Missing settings/key, null, fractions, strings, booleans and other numeric
protocol values fail construction with a diagnostic naming
`FakeTcpHeaderServer->settings->payload-protocol`. Unknown keys, invalid template
types/ranges, malformed hex options and non-object settings also fail creation.
The peers must match the payload protocol and all three port settings. Other
template values may differ: decode reads the received fake TCP data offset and
does not compare the template, options or flags with its local outgoing values.

All ports and TCP-template fields in this table belong to the **fake header**.
For example, fake TCP port 40000 can carry original UDP traffic for port 5300.
The original application port is kept in the original transport header;
`server-port` does not select or replace the backend application's port.

## Wire Rules

The server uses the same
[single-IPv4 format](../FakeTcpHeaderClient/description.md#wire-rules) and
[native checksum representation](../FakeTcpHeaderClient/description.md#native-checksum-representation)
as the client. For UDP, the layout is:

```text
[existing IPv4, protocol 6][fake TCP + options][original UDP header][application bytes]
```

For native TCP the original TCP header and its options follow fake TCP. Both
native TCP and its carrier have protocol 6; upstream always decodes and
downstream always encodes.

IHL means the actual length of the IPv4 header, including its options; fake TCP
starts immediately after that header. The existing IPv4 IHL/options, ID, DF,
TTL, DSCP/ECN and current addresses are preserved. Only protocol, total length
and IPv4 checksum are updated. Transit header changes remain after decoding.
The node stores no original addresses.

TCP and UDP checksums depend on IP addresses. To let `IpOverrider` change
addresses while the native header is hidden, the codec removes the addresses'
contribution to the native checksum before encoding and adds the current
addresses' contribution on decoding. The zero/zero calculation below does not
replace the packet's actual address fields with zeros.

Native TCP/UDP checksum address contributions are normalized to zero/zero before
encoding and restored to current addresses during decoding, retaining native
protocol and transport length. Invalid native residuals survive unless a native
repair was requested; UDP disabled zero remains zero. The fake TCP checksum uses
real current addresses and covers fake TCP plus the normalized native bytes.
A native repair request is completed before encoding. A carrier repair request
only bypasses visible IPv4/fake TCP checksum verification on decode; it does not
repair hidden native corruption or relax structure checks. Success clears the
request, while refusal preserves bytes and intent until recycling.

Incoming fake TCP must have destination `server-port` and source in the client
range. Reply fake TCP uses source `server-port` and destination `client-port + i`,
where `i` is the native flow hash modulo `client-port-count`. Request/reply
indices match when the native tuples at the two encoders are reverses. Arbitrary
rewrites can change that relationship; stable tuples within each direction still
produce stable distribution. See
[Per-Flow Carrier Ports](../FakeTcpHeaderClient/description.md#per-flow-carrier-ports).

## Receive Filtering

Capture the client's public IPv4 and fake TCP destination port:

```json
{
  "name": "raw",
  "type": "RawSocket",
  "settings": {
    "capture-filter-mode": "source-ip",
    "capture-ips": ["192.0.2.10"],
    "capture-protocols": [6],
    "capture-tcp-dest-port": 40000
  },
  "next": "carrier-addresses"
}
```

Decode rejects client ports outside its range. Reserve `server-port` between
these hosts, avoiding a genuine TCP service or ephemeral use on it: matching
native TCP would be captured and dropped. Tuple filtering is not authentication.

## Composition

There is only one set of IPv4 address fields. If they are changed to public
addresses while encoded, those public addresses remain after decoding unless
another node changes them. FakeTcpHeader does not save private addresses or
restore them automatically.

This `IpOverrider` between RawSocket and the server restores native addresses
before upstream decode and sets public addresses after downstream encode:

```json
{
  "name": "carrier-addresses",
  "type": "IpOverrider",
  "settings": {
    "up": {
      "source-ip": { "ipv4": "10.90.0.1" },
      "dest-ip": { "ipv4": "10.90.0.2" }
    },
    "down": {
      "source-ip": { "ipv4": "198.51.100.10" },
      "dest-ip": { "ipv4": "192.0.2.10" }
    }
  },
  "next": "fake-tcp-header"
}
```

The client sets `192.0.2.10 -> 198.51.100.10` upstream and restores
`10.90.0.2 -> 10.90.0.1` downstream. These are configuration choices. Omitting
restoration leaves public addresses in the decoded packet; this breaks delivery
when its receiving stack expects the private tuple. Other placements can work
when checksums and routing remain consistent.

For other fake TCP flags, place `IpManipulator` between this node and RawSocket
with `dw-tcp-bit-*` for server egress. For another visible carrier protocol, use
`protoswap-tcp` next to both codecs and capture that protocol without TCP port
qualifiers, restoring protocol 6 before decode. See
[client composition](../FakeTcpHeaderClient/description.md#composition).

## MTU and Validation

Only the fake TCP header is added: `F = 20 + outgoing options length` bytes.
The native IP packet limit is `1500 - F`: 1480 without options, 1476 with four
option bytes, and 1440 with forty. Existing IPv4 options are already part of the
native length. Configure both peers' TUN/CTP/PTC MTUs for the largest outgoing
fake header on either peer and any lower path MTU. The node advertises 60 bytes
of left padding and neither fragments, segments, discovers PMTU nor adjusts MSS.

The native MTU counts the **whole original IPv4 packet**, not just application
data. Without fake TCP options, a 1480-byte native packet becomes a 1500-byte
carrier. With a 20-byte IPv4 header and an 8-byte UDP header, the application
can put 1452 bytes of UDP data in that native packet. IPv4 options use space
inside the native packet; fake TCP options increase the added overhead. See
the [client MTU table](../FakeTcpHeaderClient/description.md#mtu-and-validation)
for all option-size limits.

Both encode and decode require complete unfragmented IPv4 datagrams. Reject MF
or nonzero fragment offset even with repair intent; preserve DF. Device ingress
must reassemble native fragments, and any transit-fragmented carrier must be
reassembled before decoding. Do not use `preserve-fragments` to feed this node.
Keep CTP UDP datagrams within the native MTU, since its larger output is
fragmented. See [client validation](../FakeTcpHeaderClient/description.md#mtu-and-validation)
for exact framing, UDP-length, TCP-offset, checksum and size rules.

Drop diagnostics name the refusal reason at network `ERROR` level. Incoming logs
include packet/max-carrier bytes; outgoing logs include packet/max-native bytes,
overhead and headroom. One log per node is allowed every five seconds across
all workers, reasons and both directions. The worker packet line remains alive.

## Limits and Detectability

The constant fake TCP template and additional native transport header are easy
to fingerprint. Stateful firewalls and NAT can drop carriers; rewriting fake TCP
ports breaks decoding. There is no authentication, encryption or reliability
at the fake TCP layer. Use appropriate traffic protection inside it. Native UDP
retains loss/reordering behavior and native TCP retains its own TCP behavior.

## Examples

[examples/server](examples/server/config.json) forwards native UDP to
`127.0.0.1:5300`, serving the client's
[UDP](../FakeTcpHeaderClient/examples/client/config.json) and
[TUN](../FakeTcpHeaderClient/examples/client-tun/config.json) examples. Both
peers select `payload-protocol: 17`, use native MTU 1480 without fake options,
and restore private addresses explicitly. Replace documentation public
addresses in RawSocket and IpOverrider, and run from each example directory
with its `core.json`. `UdpConnector` may override the backend destination;
`PacketsToConnection` retains the native tuple for replies. Native TCP instead
requires `payload-protocol: 6` on both peers and suitable TCP edges.

## Node Metadata

| Property | Value |
| --- | --- |
| `version` | `1` |
| node flags | `kNodeFlagNone` |
| `can_have_prev`, `can_have_next` | `true` |
| node and neighbour layers | `kNodeLayer3` |
| `required_padding_left` | `60` bytes |
| line state | none |

Build option: `INCLUDE_FAKE_TCP_HEADER_SERVER` (default `TRUE`). Its only module
requirements are `FakeTcpHeaderCommon` and `ww`, independent of the client and
IpManipulator modules.

The implementation is a pure packet tunnel created with `packettunnelCreate()`.
It keeps no per-line connection state.
