# FakeTcpHeaderServer Node

`FakeTcpHeaderServer` receives packets with an extra TCP-looking header from
[FakeTcpHeaderClient](../FakeTcpHeaderClient/description.md). It removes that
header and protocol byte to recover the original IPv4 traffic. For replies, it
adds both again so the client can remove them. The existing IPv4 header is
reused; there is exactly one IPv4 header.

In this page, **native** means the original packet or its original IP payload.
A **carrier** is the packet after the fake TCP header and protocol byte have been
added. Encoding adds this framing; decoding removes it.

The fake TCP layer does not establish a connection, track a TCP session, or
retransmit lost packets. Original TCP traffic still has its own real handshake
and reliability; original UDP traffic does not gain those features. The node
only transforms packets. Chain configuration determines addresses and restores
the addresses expected by the receiving TUN or connection stack.

| Event | Action |
| --- | --- |
| upstream carrier | Validate and remove fake TCP and the protocol byte, restore the tagged native protocol and forward upstream. |
| downstream native IPv4 packet | Insert fake TCP from `server-port` to `client-port + i` and the protocol byte, then forward downstream. |
| refused packet | Recycle it on its worker and emit a rate-limited diagnostic. |

## Per-Packet Protocol Byte

The client records each packet's original IPv4 protocol in one byte immediately
after fake TCP and its options. The server removes this framing and restores the
protocol from that byte. On replies, the server records the reply packet's own
protocol. One configured pair can alternate TCP, UDP, ICMP and other IPv4
protocols without a protocol setting or remembered selection.

The byte is fake TCP payload, not a header field; TCP's data offset excludes it.
The visible IPv4 protocol is TCP (6) while encoded. A separate ProtoSwap node can
change the carrier protocol later; see [Composition](#composition). These values
are IP protocol numbers, not ports or application protocols such as HTTP or DNS.

### UDP example

```text
Original packet before encoding at the client:
[IPv4 says UDP][original UDP header][data]

Packet received from the client:
[IPv4 says TCP][fake TCP + options][17: one byte][original UDP header][data]

Packet after server decoding:
[IPv4 says UDP][original UDP header][data]
```

The server removes fake TCP and the byte containing 17, then restores UDP.
The UDP header and application data remain. Replies undergo the reverse
operation at the server, then the client decodes them. This framing gives UDP
no delivery or ordering guarantee.

### TCP example

```text
Original packet before encoding at the client:
[IPv4 says TCP][original TCP header][data]

Packet received from the client:
[IPv4 says TCP][fake TCP + options][6: one byte][original TCP header][data]

Packet after server decoding:
[IPv4 says TCP][original TCP header][data]
```

The encoded packet contains **two TCP headers and one IPv4 header**. The server
removes the fake TCP header and protocol byte. The original TCP header keeps
its options, sequence numbers, acknowledgments and flags; its checksum is
adjusted for the current addresses as explained in [Wire Rules](#wire-rules).

The original TCP endpoints still perform their own handshake and
retransmissions. An original SYN is carried behind a fake ACK|PSH header and
reaches the receiving stack as a SYN after decoding. The node's configured
`sequence`, `acknowledgment`, `window`, and `options` affect only the fake header,
not the real TCP connection.

### ICMP example

```text
Original packet before encoding at the client:
[IPv4 says ICMP][original ICMP header][ICMP message body]

Packet received from the client:
[IPv4 says TCP][fake TCP + options][1: one byte][original ICMP header][ICMP message body]

Packet after server decoding:
[IPv4 says ICMP][original ICMP header][ICMP message body]
```

The complete ICMP message is preserved without address normalization. ICMP's
checksum has no surrounding IPv4-address pseudo-header. Quoted IP headers in
ICMP errors stay unchanged; this does not translate their embedded addresses.

### Other IPv4 protocols

All byte values `0..255` are representable. TCP, UDP and ICMP receive structural
checks; other native bodies are opaque and byte-preserved, including an empty
body. Reserved or unknown values do not imply OS or downstream support.

Opaque carriage promises no arbitrary address rewriting or generic integrity
repair: protocols such as UDP-Lite or AH can protect addresses or other header
fields. Preserve or restore required fields, or use protocol-aware handling
elsewhere. `ConnectionToPackets` and `PacketsToConnection` remain TCP/UDP-only;
a suitable packet path such as TUN can use the broader carriage.

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

The listener/connector examples above use UDP because of their endpoints.
For native TCP, use TCP listeners/connectors with the same packet bridges.
`ConnectionToPackets` (CTP) and `PacketsToConnection` (PTC) support TCP/UDP;
ICMP and opaque protocols need suitable packet endpoints at both ends. Upstream
means toward the next node and downstream toward the previous node, on the
server as well as the client.

## Configuration Example

```json
{
  "name": "fake-tcp-header",
  "type": "FakeTcpHeaderServer",
  "settings": {
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

Omitted `settings` and `{}` select all defaults. No native-protocol setting is
needed; each received packet supplies its own protocol byte.

| Setting | Default | Meaning |
| --- | --- | --- |
| `server-port` | `40000` | Fake TCP server port, integer `1..65535`. |
| `client-port` | `40001` | First fake TCP client port, integer `1..65535`. |
| `client-port-count` | `16` | Integer `1..1024`; client range must end at or below `65535` and exclude `server-port`. |
| `sequence` | `0` | Outgoing fake TCP sequence, integer `0..4294967295`. |
| `acknowledgment` | `0` | Outgoing fake TCP acknowledgment, integer `0..4294967295`. |
| `window` | `65535` | Fake TCP window, integer `0..65535`. |
| `urgent-pointer` | `0` | Fake TCP urgent pointer, integer `0..65535`. |
| `options` | `""` | Verbatim hexadecimal fake TCP options: `0..40` bytes, in four-byte groups. |

Unknown keys, including `payload-protocol`, invalid template types/ranges,
malformed hex options and non-object settings fail creation with a diagnostic
naming the key, for example `FakeTcpHeaderServer->settings->server-port`.
The peers must match all three port settings. Other template values may differ:
decode reads the received fake TCP data offset and protocol byte and does not
compare the template, options or flags with its local outgoing values.

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
[existing IPv4, protocol 6][fake TCP + options][17: one byte][original UDP header][application bytes]
```

For native TCP the original TCP header and its options follow the byte containing
6. Both native TCP and its carrier have protocol 6; upstream always decodes and
downstream always encodes. With actual IPv4 length `H` and received fake TCP
length `F`, the tag is at `H + F` and native bytes start at `H + F + 1`. TCP's data
offset is `F / 4`, excluding the tag. Its checksum and IPv4 total length include
the tag, while native checksums exclude it. Decode uses the received data offset,
independently of local outgoing options.

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
real current addresses and covers fake TCP, the protocol byte and the entire
native body. UDP checksum coverage uses its declared length, including when
permitted IP payload padding follows it; enabled UDP arithmetic zero is `0xffff`
and TCP zero remains an ordinary checksum value.

ICMP receives no address normalization and keeps its complete message bytes
unless native repair was requested. Opaque protocols receive no checksum parsing
or address normalization. Native repair uses the shared full-packet helper for
TCP, UDP and ICMP; for an opaque protocol it repairs only the IPv4 header and
leaves the opaque body untouched. Known-protocol validation is structural and
does not normally repair or reject an invalid native checksum.

A carrier repair request bypasses only visible IPv4/fake TCP checksum verification
on decode. It never repairs hidden native TCP, UDP, ICMP or opaque bytes, nor
relaxes framing, ports, tag presence, native shape, fragments or size checks.
Decode restores TCP/UDP address contributions and recomputes only the surviving
IPv4 checksum. Success clears the request, while refusal preserves bytes,
headroom, cursor, length and intent until recycling.

Incoming fake TCP must have destination `server-port` and source in the client
range. Reply fake TCP uses source `server-port` and destination `client-port + i`,
where `i` is the native flow hash modulo `client-port-count`. The existing helper
recognizes TCP/UDP/SCTP ports when present and otherwise uses its existing
fallback; per-session ICMP or opaque distribution is not promised. Request/reply
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

The overhead is `O = F + 1`, where `F = 20 + outgoing options length` counts
only fake TCP and the additional byte records the native protocol. Thus overhead
is `21..61` bytes and the native IP packet limit is `1500 - O`: 1479 without
options, 1475 with four option bytes, and 1439 with forty. Existing IPv4 options
are already part of native length. Configure both peers' TUN/CTP/PTC and core MTUs
for the largest outgoing fake header plus protocol byte and any lower path MTU.
The node advertises 61 bytes of left padding and neither fragments, segments,
discovers PMTU nor adjusts MSS. It moves only the IPv4 header; the native body
stays in place and requires no extra tail space.

The native MTU counts the **whole original IPv4 packet**, not just application
data. Without fake TCP options, a 1479-byte native packet becomes a 1500-byte
carrier. With a 20-byte IPv4 header and an 8-byte UDP header, the application
can put 1451 bytes of UDP data in that native packet. With four fake option bytes,
the UDP data limit is 1447 bytes. IPv4 options use space inside the native packet;
fake TCP options increase the added overhead. See the
[client MTU table](../FakeTcpHeaderClient/description.md#mtu-and-validation).

Both encode and decode require complete unfragmented IPv4 datagrams for every
native protocol. Encode rejects MF or nonzero fragment offset before native
transport parsing, repair or any mutation, even with repair intent. This drops
first, middle and final fragments. Decode also rejects MF or a nonzero offset;
DF alone remains accepted and preserved. Reassemble native fragments before
encode and transit-fragmented carriers before decode. `preserve-fragments` does
not permit fragments. Keep CTP UDP datagrams within the native MTU, since its
larger output is fragmented.

Decode requires at least one byte after the received fake TCP header for the
tag. TCP, UDP and ICMP require their native minimum headers after that byte;
TCP data offset and UDP declared length must fit the native span. Opaque bodies
can be empty, so a tag-only carrier is valid only for opaque protocols. All
protocol-byte values are representable, including zero. Exact IPv4 framing,
ports, final size and normal visible checksum verification remain mandatory.
See [client validation](../FakeTcpHeaderClient/description.md#mtu-and-validation)
for the complete rules.

Drop diagnostics name the refusal reason at network `ERROR` level. Incoming logs
include packet/max-carrier bytes; outgoing logs include packet/max-native bytes,
overhead and headroom. One log per node is allowed every five seconds across
all workers, reasons and both directions. The worker packet line remains alive.

## Limits and Detectability

The constant fake TCP template and tagged native payload are easy to fingerprint. Stateful firewalls and NAT can drop carriers; rewriting fake TCP
ports breaks decoding. There is no authentication, encryption or reliability
at the fake TCP layer. Use appropriate traffic protection inside it. Native UDP
retains loss/reordering behavior and native TCP retains its own TCP behavior.

## Examples

[examples/server](examples/server/config.json) forwards native UDP to
`127.0.0.1:5300`, serving the client's
[UDP](../FakeTcpHeaderClient/examples/client/config.json) and
[TUN](../FakeTcpHeaderClient/examples/client-tun/config.json) examples. Both
peers use native MTU 1479 without fake options and restore private addresses
explicitly. These examples carry UDP because of their PTC/UDP endpoints, not a
FakeTcpHeader protocol setting. Replace documentation public addresses in
RawSocket and IpOverrider, and run from each example directory with its
`core.json`. `UdpConnector` may override the backend destination;
`PacketsToConnection` retains the native tuple for replies. Native TCP needs
suitable TCP edges; broader protocols need suitable packet endpoints such as
TUN at both ends.

## Node Metadata

| Property | Value |
| --- | --- |
| `version` | `1` |
| node flags | `kNodeFlagNone` |
| `can_have_prev`, `can_have_next` | `true` |
| node and neighbour layers | `kNodeLayer3` |
| `required_padding_left` | `61` bytes |
| line state | none |

Build option: `INCLUDE_FAKE_TCP_HEADER_SERVER` (default `TRUE`). Its only module
requirements are `FakeTcpHeaderCommon` and `ww`, independent of the client and
IpManipulator modules.

The implementation is a pure packet tunnel created with `packettunnelCreate()`.
It keeps no per-line connection state.
