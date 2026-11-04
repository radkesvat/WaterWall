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
retransmit lost packets. By default, each client port starts from an
independently chosen random sequence number, then advances by the fake TCP
payload length using its own counter. Its acknowledgment defaults to a fixed
zero; optional modes choose random values per node, port or packet. Original
TCP traffic still has its own real handshake and reliability; original UDP
traffic does not gain those features. The node only
transforms packets. Chain configuration determines addresses and restores the
addresses expected by the receiving TUN or connection stack.

| Event | Action |
| --- | --- |
| upstream carrier | Validate and remove fake TCP and the protocol byte, restore the tagged native protocol and forward upstream. |
| downstream native IPv4 packet | Insert fake TCP from `server-port` to `first client port + i` and the protocol byte, then forward downstream. |
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
retransmissions. With the default flags, an original SYN is carried behind a
fake ACK|PSH header and reaches the receiving stack as a SYN after decoding.
The node's configured `sequence`, `acknowledgment`, `flags`, `window`, and
`options` affect only the fake header, not the real TCP connection.

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
    "client-port-range": [40001, 40016],
    "sequence": "random_port",
    "increment-sequence": true,
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
| `client-port` | unset | Use exactly one fake TCP client port. Integer `1..65535`; mutually exclusive with `client-port-range`. |
| `client-port-range` | `[40001, 40016]` when neither client setting is supplied | Inclusive `[first, last]` range of integer ports `1..65535`, in ascending order, containing `1..1024` ports. |
| `increment-sequence` | `true` | Advance the selected port's sequence by fake TCP payload length, plus one for each chosen SYN or FIN bit. Boolean only. Set `false` to use a fixed sequence. |
| `sequence` | `"random_port"` | Starting value: an integer `0..4294967295`, `"random_node"` for one random start shared by all client ports, or `"random_port"` for an independent random start per port. See [Sequence Progression](#sequence-progression). |
| `acknowledgment` | `0` | An integer `0..4294967295`, `"random_node"`, `"random_port"`, or `"random_packet"`. Never derived from received packets. See [Acknowledgment Modes](#acknowledgment-modes). |
| `increment-acknowledgment` | `false` | Advance the selected client port's ACK by one per successfully encoded packet. Boolean only; incompatible with `"acknowledgment": "random_packet"`. |
| `flags` | `[{"ack": true, "psh": true}]` | Ordered script of `1..32` flag objects, tracked per client port; repeats the last entry. See [Outgoing Flag Script](#outgoing-flag-script). |
| `window` | `65535` | Fake TCP window, integer `0..65535`. |
| `urgent-pointer` | `0` | Fake TCP urgent pointer, integer `0..65535`. |
| `options` | `""` | Verbatim hexadecimal fake TCP options: `0..40` bytes, in four-byte groups. |

`"client-port": 40001` uses only port 40001. `"client-port-range": [40001, 40016]`
uses all 16 ports from 40001 through 40016, including both endpoints. A range
such as `[40001, 40001]` also selects exactly one port. `client-port` accepts an
integer, not an array; `client-port-range` accepts exactly two integers, not a
list of separate ports. Supplying both keys is invalid. With neither key, the
client range is `40001..40016`. `server-port` must be outside the selected client
ports, including when the default range is used.

Unknown keys, including `payload-protocol` and `client-port-count`, invalid
template types/ranges, malformed hex options and non-object settings fail creation with a diagnostic
naming the key, for example `FakeTcpHeaderServer->settings->server-port`.
The peers must match `server-port` and the selected client port or range. Their
sequence modes and other template values may differ: decode reads the received
fake TCP data offset and protocol byte and does not compare the template,
options or flags with its local outgoing values.

All ports and TCP-template fields in this table belong to the **fake header**.
For example, fake TCP port 40000 can carry original UDP traffic for port 5300.
The original application port is kept in the original transport header;
`server-port` does not select or replace the backend application's port.

## Outgoing Flag Script

`flags` selects an ordered script for the fake TCP header. The default is:

```json
{
  "flags": [{"ack": true, "psh": true}]
}
```

This one-entry script uses ACK|PSH (`0x18`) on every outgoing carrier. To use a
different pattern, supply `1..32` objects. Each object accepts the flag names
`fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `ece`, and `cwr`, with JSON boolean
values. An omitted flag is `false`; `{}` is valid and sets no flags. Unknown or
duplicate flag names, embedded NUL characters, non-boolean values, non-object
entries, an empty array, and more than 32 entries are rejected. For example,
`"syn": 1` and `"ack": "true"` are invalid. `options` remains a separate
hexadecimal string; it is not part of this script.

For example:

```json
{
  "flags": [
    {"syn": true},
    {"fin": true},
    {"ack": true, "fin": true, "cwr": true}
  ]
}
```

Each selected client port starts at the first entry when the node is created.
Each successfully encoded packet uses its current entry, then moves to the
next. **The last entry repeats forever**; the script does not loop back.
For packets selecting the same client port, this example produces:

| Successful encoding | Fake TCP flags | Flag byte |
| --- | --- | --- |
| First | SYN | `0x02` |
| Second | FIN | `0x01` |
| Third | ACK, FIN, CWR | `0x91` |
| Fourth and later | ACK, FIN, CWR | `0x91` |

Another client port starts its own script at the first entry. Workers, native
flows and peers mapping to the same client port share its position safely.
New native connections do not restart it; recreating the node does. Client
upstream and server downstream have independent scripts, and the two peers
may configure different scripts.

Every entry still carries the native packet that triggered encoding. A SYN
entry does not create an additional handshake packet or wait for a response;
FIN and RST do not close the node, its packet line or the native connection.
This is an explicitly selected header pattern, not a TCP session or reliability
mechanism. Worker scheduling and network reordering can change wire/arrival
order. A refused encoding does not advance the script, draw a per-packet ACK
or advance either counter; a drop after successful encoding does not undo them.

With sequence incrementing enabled, the chosen fake SYN and FIN bits each add
one to that packet's sequence increment. Both set means two extra sequence
positions; other flags add none. See [Sequence Progression](#sequence-progression).
ACK generation and optional ACK incrementing run independently, even when the
script sets `ack` to `false`. The ACK field still contains the configured
numeric, random or counter value. The carrier checksum covers the actual flags,
sequence and ACK written. Decode does not interpret flag meanings, compare them
with its own script, change local script state or require an expected order;
normal packet geometry and checksum checks remain in force.

## Sequence Progression

The recommended profile is also the default:

```json
{
  "sequence": "random_port",
  "increment-sequence": true,
  "acknowledgment": 0,
  "increment-acknowledgment": false,
  "flags": [{"ack": true, "psh": true}]
}
```

`sequence` chooses a starting value; `increment-sequence` controls what happens
on later packets. The accepted starting-value choices are:

| `sequence` value | When the node is created | With `increment-sequence: false` |
| --- | --- | --- |
| An integer `0..4294967295` | Every selected client port starts from that number. | Every outgoing packet uses that number. |
| `"random_node"` | Draw one random 32-bit number and use it as every port's starting value. | Every outgoing packet uses that one chosen number. |
| `"random_port"` (default) | Draw an independent random 32-bit starting value for each selected client port. | Each port repeatedly uses its own chosen number. |

Random starting values are chosen during node creation, before any packet is
sent, including when incrementing is disabled. They are not chosen again on
each packet or each new native connection. All 32-bit values, including zero,
are valid, and separate random draws can happen to match; uniqueness is not
guaranteed. Recreating the node draws fresh values in either random mode. A
numeric setting starts from the configured number again.

With `"increment-sequence": true`, each selected client port has its own
outgoing counter. `"random_node"` gives the counters the same initial value,
but they can diverge as traffic uses different ports. With `"random_port"`, each
counter starts from its independently chosen value. Each accepted encoding
uses the selected counter's current value in the fake TCP header, then advances
it by:

```text
1 protocol byte + original IPv4 payload length
+ 1 if the chosen fake SYN bit is set
+ 1 if the chosen fake FIN bit is set
```

The server uses this logic when encoding a downstream packet from `server-port`
to the selected client port. The original IPv4 payload includes the native
TCP/UDP header and data, or the complete ICMP/opaque body. IPv4 and fake TCP
headers/options are excluded. SYN and FIN each add one sequence position, not
a packet byte. For example, with the default ACK|PSH flags, a UDP packet with
100 application bytes advances its port's counter by `1 + 8 + 100 = 109`:
a starting sequence of `1000` becomes `1109` for the next packet selecting
that port.

Packets selecting another client port advance that port's separate counter.
All workers of one node instance share these counters safely. Native flows and
peers that select the same port share its counter; there is no per-connection
sequence state. A new native flow does not reset it. Arithmetic wraps modulo
`2^32`.

Packets refused by this encoder do not advance a counter. Once encoding
succeeds, later drops do not undo the increment. Worker scheduling and network
reordering can change arrival order, so these counters do not guarantee a
continuous TCP sequence as observed by a receiver. The fake TCP checksum is
calculated using the sequence actually written into each packet.

With `"increment-sequence": false`, the chosen starting values stay fixed as
shown in the table. Only JSON booleans are accepted for this setting; strings,
numbers and `null` are invalid. For `sequence`, only an integer in the stated
range or the exact strings `"random_node"` and `"random_port"` are accepted.
There is no mode that chooses a fresh random sequence for every packet.

Acknowledgment selection is independent of sequence progression, as explained
below. Receiving a packet neither advances an outgoing counter nor updates an
ACK value; ACKs are never derived from the peer's traffic.

The client uses this logic when encoding upstream; the server uses it when
encoding downstream. They have independent counters and can use different
modes or initial values. Decoding does not gate, reorder or drop packets based
on sequence or acknowledgment values. This approximate byte progression adds
no handshake, retransmission, flow control or delivery guarantee, and does not
promise acceptance by TCP-aware networks.

See the client's [worked sequence example](../FakeTcpHeaderClient/description.md#sequence-progression).

## Acknowledgment Modes

`acknowledgment` controls the fake header's ACK value independently of
`sequence` and `increment-sequence`. It is never calculated from packets
received from the peer. `increment-acknowledgment` defaults to `false`; enable
it to use a separate counter for each selected client port.

| `acknowledgment` value | With `increment-acknowledgment: false` (default) | With `increment-acknowledgment: true` |
| --- | --- | --- |
| An integer `0..4294967295` (default `0`) | Write that fixed number into every outgoing fake header. | Start every client port's counter at that number. |
| `"random_node"` | Draw one random 32-bit value during node creation; use it for every outgoing packet on all selected client ports. | Start every client port's counter at the same chosen random value; ports then advance independently. |
| `"random_port"` | Draw an independent random 32-bit value for each selected client port during creation; keep each port's chosen value fixed. | Start each port's counter at its independently chosen random value. |
| `"random_packet"` | Draw a fresh random 32-bit value for each successfully encoded packet. | Invalid combination; node creation fails. |

ACK draws are separate from sequence draws. All 32-bit values, including zero,
are possible; separate draws can match, even on consecutive packets in
`random_packet` mode. Random does not mean unique. Creation-time ACK values
and any counters are shared by all workers and by all native flows selecting
that port. New native connections do not redraw or reset them. Recreating the
node draws new values for the creation-time random modes or restores the
configured numeric start.

With `"increment-acknowledgment": true`, each successful encoding writes the
selected port's current ACK, then advances its counter by **one**, regardless
of payload size. For example:

```json
{
  "acknowledgment": 5000,
  "increment-acknowledgment": true
}
```

Three packets selecting the same client port use ACKs `5000`, `5001`, and
`5002`. Another port starts its own counter at `5000`. If `acknowledgment` is
omitted, the counters start at `0`. Arithmetic wraps modulo `2^32`, so
`4294967295` is followed by `0`. Worker scheduling and network reordering can
change arrival order; consecutive values are not guaranteed on the wire.
This is a synthetic packet counter, not a real TCP acknowledgment or a count
of received bytes.

To keep the default sequence progression while varying the apparent ACK history
randomly on every packet, explicitly select:

```json
{
  "sequence": "random_port",
  "increment-sequence": true,
  "acknowledgment": "random_packet",
  "increment-acknowledgment": false
}
```

`random_packet` neither disables sequence incrementing nor requires it to be
disabled. It also works with `"increment-sequence": false`. Likewise, ACK
incrementing can be enabled with either sequence setting. Combining
`"acknowledgment": "random_packet"` with `"increment-acknowledgment": true`
is rejected instead of silently changing either setting.

The defaults remain a fixed ACK of `0` and no ACK incrementing; all other ACK
behavior requires explicit selection. `acknowledgment` accepts only integers
in the stated range and the exact strings in the table. Numeric strings,
other strings, booleans, fractions and `null` are invalid.
`increment-acknowledgment` accepts only JSON `true` or `false`; strings,
numbers and `null` are invalid.

A refused encoding draws no per-packet ACK and advances neither sequence nor
ACK state. After successful encoding, a later drop does not undo a draw or
counter increment. The fake TCP checksum covers the sequence and acknowledgment
actually written into that packet. Decode neither draws an ACK nor advances
either counter, and does not check these fields against local outgoing settings;
it retains normal carrier checksum verification.

Randomizing or incrementing ACKs can deliberately perturb the apparent
acknowledgment history. Neither tracks received bytes or confirms delivery.
An observer might ignore inconsistent values or recognize the pattern; no
improvement in concealment or network acceptance is guaranteed.

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
range. Reply fake TCP uses source `server-port` and destination
`first client port + i`, where `i` is the native flow hash modulo the number of client ports. A scalar
`client-port` selects one port, so its index is always zero. The existing helper
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

Use this node's `flags` script to choose outgoing fake TCP flags. An
`IpManipulator` between this node and RawSocket can further rewrite them with
`dw-tcp-bit-*` for server egress, but those later rewrites do not change the
sequence increment already reserved by this node. For another visible carrier
protocol, use `protoswap-tcp` next to both codecs and capture that protocol without TCP port
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

The fake TCP framing and tagged native payload are easy to fingerprint. Stateful firewalls and NAT can drop carriers; rewriting fake TCP
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
It keeps no per-line connection state. Sequence counters, optional ACK counters,
flag-script positions and any fixed random ACK values belong to the node
instance and are shared across its workers.
