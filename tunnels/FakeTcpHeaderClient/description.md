# FakeTcpHeaderClient Node

`FakeTcpHeaderClient` adds an extra TCP-looking header to an existing IPv4
packet. Its peer, [FakeTcpHeaderServer](../FakeTcpHeaderServer/description.md),
removes that header and its protocol byte to recover the original IPv4 traffic.
Replies take the reverse path: the server adds both and the client removes them.
The existing IPv4 header is reused, so there is exactly one IPv4 header.

In this page, **native** means the original packet or its original IP payload.
A **carrier** is the packet after the fake TCP header and protocol byte have been
added. Encoding adds this framing; decoding removes it.

The fake TCP layer does not establish a TCP connection, track a TCP session,
or retransmit lost packets. By default, each client port starts from an
independently chosen random sequence number, then advances by the fake TCP
payload length using its own counter. Its acknowledgment stays fixed. Original TCP traffic still has its own real TCP
behavior, as explained below; original UDP traffic does not gain TCP reliability.

The node only transforms packets. It does not select IP addresses or remember
the original ones. Chain configuration, including `IpOverrider`, supplies public
addresses and restores the addresses expected by the receiving stack.

| Event | Action |
| --- | --- |
| upstream native IPv4 packet | Insert fake TCP from `first client port + i` to `server-port` and the protocol byte, then forward upstream. |
| downstream carrier | Validate and remove fake TCP and the protocol byte, then forward the native packet downstream. |
| refused packet | Recycle it on its worker and emit a rate-limited diagnostic. |

## Per-Packet Protocol Byte

The encoder copies the original IPv4 Protocol byte immediately after fake TCP
and its options. The receiver reads this byte and restores the original IPv4
protocol. One configured pair can therefore carry TCP, UDP, ICMP and other IPv4
protocols packet by packet, with no protocol setting or remembered selection.

The byte is the first byte of the fake TCP **payload**, not part of its header.
The visible IPv4 protocol is always TCP (6) while encoded. A separate ProtoSwap
node can change that carrier protocol later; see [Composition](#composition).
The values below are IP protocol numbers, not port numbers or application
protocols such as HTTP or DNS.

### UDP example

```text
Before encoding:
[IPv4 says UDP][original UDP header][data]

Between the FakeTcpHeader peers:
[IPv4 says TCP][fake TCP + options][17: one byte][original UDP header][data]

After decoding:
[IPv4 says UDP][original UDP header][data]
```

The receiver removes fake TCP and the byte containing 17, then restores UDP.
The original UDP header and application data remain; UDP gains no delivery or
ordering guarantee.

### TCP example

```text
Before encoding:
[IPv4 says TCP][original TCP header][data]

Between the FakeTcpHeader peers:
[IPv4 says TCP][fake TCP + options][6: one byte][original TCP header][data]

After decoding:
[IPv4 says TCP][original TCP header][data]
```

There are **two TCP headers while encoded**, but only one IPv4 header. The
receiver removes the fake TCP header and protocol byte. The original TCP header,
including its options, sequence numbers, acknowledgments and flags, is retained.
Its checksum is adjusted as described in
[Native Checksum Representation](#native-checksum-representation).

The original TCP endpoints still perform their real handshake and
retransmissions. For example, an original SYN packet is carried behind the fake
ACK|PSH header; after decoding, the original SYN reaches the receiving TCP stack.
The node's `sequence`, `acknowledgment`, `window`, and `options` settings control
only the fake header. They do not replace the real TCP connection's fields.

### ICMP example

```text
Before encoding:
[IPv4 says ICMP][original ICMP header][ICMP message body]

Between the FakeTcpHeader peers:
[IPv4 says TCP][fake TCP + options][1: one byte][original ICMP header][ICMP message body]

After decoding:
[IPv4 says ICMP][original ICMP header][ICMP message body]
```

ICMP is preserved as a complete message. Its checksum does not include the
surrounding IPv4 addresses, so it needs no address normalization. Quoted IP
headers inside ICMP errors stay as carried bytes; this is not address translation
of those quoted headers.

### Other IPv4 protocols

Every protocol byte value `0..255` is representable. Apart from the structural
checks for TCP, UDP and ICMP, the native IP payload is opaque and its bytes are
preserved, including an empty payload. Reserved or unknown values are carried
without claiming that the OS or a downstream node implements them.

Opaque carriage does not promise address-independent integrity or generic
checksum repair. UDP-Lite, AH and other protocols can protect addresses or other
header fields. Preserve or restore the fields they require, or provide
protocol-aware handling elsewhere. A TUN path can carry broader protocols;
`ConnectionToPackets` and `PacketsToConnection` remain TCP/UDP-only.

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

The listener/connector chains shown above carry UDP because of their endpoints.
For native TCP, use TCP listeners/connectors with the same packet bridges.
`ConnectionToPackets` (CTP) and `PacketsToConnection` (PTC) support only TCP/UDP;
use suitable packet paths such as TUN at both ends for ICMP or opaque protocols.
Upstream means toward the next node; downstream means toward the previous node.
Client/server names do not reverse these directions.

## Configuration Example

```json
{
  "name": "fake-tcp-header",
  "type": "FakeTcpHeaderClient",
  "settings": {
    "server-port": 40000,
    "client-port-range": [40001, 40016],
    "sequence": "random_port",
    "increment-sequence": true,
    "acknowledgment": 67890,
    "window": 65535,
    "urgent-pointer": 0,
    "options": "01010101"
  },
  "next": "carrier-addresses"
}
```

Both nodes accept the same keys. Omitted `settings` and `{}` select all defaults;
no native-protocol setting is needed.

| Setting | Default | Meaning |
| --- | --- | --- |
| `server-port` | `40000` | Fake TCP server port. Integer `1..65535`. |
| `client-port` | unset | Use exactly one fake TCP client port. Integer `1..65535`; mutually exclusive with `client-port-range`. |
| `client-port-range` | `[40001, 40016]` when neither client setting is supplied | Inclusive `[first, last]` range of integer ports `1..65535`, in ascending order, containing `1..1024` ports. |
| `increment-sequence` | `true` | Advance the outgoing sequence counter for the selected client port by the fake TCP payload length. Boolean only. Set `false` to use a fixed sequence. |
| `sequence` | `"random_port"` | Starting value: an integer `0..4294967295`, `"random_node"` for one random start shared by all client ports, or `"random_port"` for an independent random start per port. See [Sequence Progression](#sequence-progression). |
| `acknowledgment` | `0` | Fixed acknowledgment number of every outgoing fake header. Integer `0..4294967295`; never derived from received packets. |
| `window` | `65535` | Fake TCP window. Integer `0..65535`. |
| `urgent-pointer` | `0` | Fake TCP urgent pointer. Integer `0..65535`. |
| `options` | `""` | Hexadecimal fake TCP options, `0..40` bytes in multiples of 4, emitted verbatim. Include any NOP/EOL padding. |

`"client-port": 40001` uses only port 40001. `"client-port-range": [40001, 40016]`
uses all 16 ports from 40001 through 40016, including both endpoints. A range
such as `[40001, 40001]` also selects exactly one port. `client-port` accepts an
integer, not an array; `client-port-range` accepts exactly two integers, not a
list of separate ports. Supplying both keys is invalid. With neither key, the
client range is `40001..40016`. `server-port` must be outside the selected client
ports, including when the default range is used.

Unknown keys, including `payload-protocol` and `client-port-count`, wrong types, fractions and
out-of-range template values fail creation with a diagnostic naming the key,
for example `FakeTcpHeaderClient->settings->server-port`. A non-object `settings`
is invalid. Invalid hexadecimal options, odd hex length, lengths not divisible
by four bytes, and lengths above 40 bytes are refused. There are no address,
MTU, flag or alternative carrier-protocol settings here.

Both peers must agree on `server-port` and the selected client port or range.
Their sequence mode, sequence, acknowledgment, window, urgent pointer and options
may differ. Receive reads the incoming data offset and protocol byte; it does not
compare these fields or flags with its own outgoing values.

All port and TCP-template settings in this table describe the **fake header**.
For example, native UDP traffic for port 5300 can use fake TCP destination port
40000 on the network. The original UDP port remains in the original UDP header;
setting `server-port` does not change the application's destination port.

## Sequence Progression

The recommended profile is also the default:

```json
{
  "sequence": "random_port",
  "increment-sequence": true
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
```

The original IPv4 payload includes the native TCP/UDP header and its data, or
the complete ICMP/opaque body. Neither the IPv4 header nor the fake TCP header
and options count toward the increment. For example, on one selected client
port with `"sequence": 1000`:

| Packet | Original UDP data | Fake TCP payload length | Sequence used | Next counter value |
| --- | --- | --- | --- | --- |
| First | 100 bytes | `1 + 8 + 100 = 109` | `1000` | `1109` |
| Second | 50 bytes | `1 + 8 + 50 = 59` | `1109` | `1168` |

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

In every mode, `acknowledgment` remains fixed at its configured value. Sending a
packet does not acknowledge the peer's traffic, and receiving one neither
advances an outgoing counter nor updates an acknowledgment.

The client uses this logic when encoding upstream; the server uses it when
encoding downstream. They have independent counters and can use different
modes or initial values. Decoding does not gate, reorder or drop packets based
on sequence or acknowledgment values. This approximate byte progression adds
no handshake, retransmission, flow control or delivery guarantee, and does not
promise acceptance by TCP-aware networks.

## Wire Rules

For an original protocol byte `P`:

```text
native:  [existing IPv4, protocol P][original IP payload]
carrier: [same IPv4, protocol 6][fake TCP + options][P: one byte][original IP payload]
decoded: [same IPv4, protocol P][original IP payload]
```

Let `H` be the actual IPv4 header length and `F` the received fake TCP header
length. The protocol byte is at `H + F`; native bytes begin at `H + F + 1`.
Fake TCP's data offset is `F / 4` and excludes the protocol byte. Its checksum
and IPv4 total length include that byte; native checksums exclude it. Decode
uses the received data offset, independently of local outgoing options.

For native TCP, both native and encoded packets have IP protocol 6. Callback
direction selects encode or decode, never the visible protocol alone.

IPv4 IHL is the length of the existing IPv4 header, including any IPv4 options.
That actual length locates fake TCP. The transform preserves
source/destination, IHL/options, identification, DF, TTL and DSCP/ECN. It changes
protocol and total length and recomputes the IPv4 checksum over the actual IHL.
Transit TTL or ECN changes remain visible after decoding. There is no protected
inner IPv4 header and no saved address to recover.

Fake TCP uses the configured ports and template, flags ACK|PSH (`0x18`), and a
valid checksum over its header/options, protocol byte and complete native body,
plus a protocol-6 pseudo-header with
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

ICMP has no surrounding IPv4-address pseudo-header. Its complete message,
including checksum bytes, stays unchanged unless native repair is requested.
Opaque protocols receive no transport checksum parsing or address adjustment;
their body bytes are preserved without any claim of integrity verification.

A pending native checksum request is completed before insertion and before
TCP/UDP normalization. It repairs TCP, UDP and ICMP using the shared full-packet
helper. For opaque protocols it repairs only the IPv4 header, leaving the opaque
body untouched. Without this request, known-protocol validation checks structure,
not native checksum validity.

On decode a request makes the visible IPv4/fake TCP checksums non-authoritative
but does not waive framing, ports, protocol-byte presence, native shape, fragments
or size checks. It never authorizes repair of hidden TCP, UDP, ICMP or opaque
bytes. Decode restores TCP/UDP address contributions and recomputes only the
surviving IPv4 header checksum. Successful encode/decode clears the consumed
request. Arbitrary hidden transport or payload edits while encoded require a
transform that understands this representation.

## Per-Flow Carrier Ports

Each native packet selects a client carrier port before insertion. The first
client port and number of client ports come from the selected scalar or inclusive
range. For `[40001, 40016]`, these are 40001 and 16; a scalar selects one port.
The number of available ports is not a connection limit: different native flows
can select the same port, and no real TCP listeners or connections are opened.

Selection uses:

```text
i = deviceFlowWorkerHash(native packet) % number of client ports

client -> server: source first client port + i, destination server-port
server -> client: source server-port,           destination first client port + i
```

The fallback index is zero when hashing is unavailable. The existing helper
recognizes native TCP/UDP/SCTP ports when present and otherwise uses its existing
fallback; it does not promise per-session ICMP or opaque distribution. The hash
is endpoint-symmetric: request and reply select the same index when their tuples
at the two encoders are reverses. Arbitrary address rewrites can change that
relationship. A stable native tuple in each direction still gives stable
receive distribution.

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

With `H` the existing IPv4 IHL (`20..60`), `F = 20 + options length`
(`20..60`) and one protocol byte:

```text
native length    = H + original IP payload length
inserted overhead O = F + 1                     (21..61 bytes)
encoded length   = native length + O
maximum native IPv4 packet length = 1500 - outgoing O
```

| Fake TCP options | Overhead | Maximum native IP packet | UDP application bytes with 20-byte IPv4 |
| --- | --- | --- | --- |
| 0 bytes | 21 bytes | 1479 bytes | 1451 bytes |
| 4 bytes | 25 bytes | 1475 bytes | 1447 bytes |
| 40 bytes | 61 bytes | 1439 bytes | 1411 bytes |

These native MTUs count the **whole original IPv4 packet**, including its IP
header and original payload. Without fake TCP options, a 1479-byte native packet
becomes a 1500-byte carrier. With a 20-byte IPv4 header and an 8-byte UDP header,
that leaves 1451 bytes for the application's UDP data. IPv4 options consume
space inside the native packet, while fake TCP options increase the added
overhead.

Set `TunDevice.device-mtu`, `ConnectionToPackets.mtu` and
`PacketsToConnection.mtu` (otherwise inherited from core `misc.mtu`) to fit
the largest outgoing fake header plus protocol byte used by either peer. A
lower path MTU requires smaller values. The codec neither fragments nor segments,
discovers PMTU, or adjusts native TCP MSS. It advertises 61 bytes of left padding;
encode needs its outgoing `O` bytes and moves only the existing IPv4 header.
Native body bytes remain in place; no extra tail space is needed.

Both entry points require exactly one complete, unfragmented IPv4 datagram,
for every original protocol. Encode rejects MF or a nonzero fragment offset
**before** native transport parsing, checksum repair or any buffer mutation.
This drops first, middle and final fragments, even with a repair request. Decode
also refuses MF or a nonzero offset. DF alone is accepted and preserved. Use
upstream device reassembly (`fragment-policy: "reassemble"`, the default) for
fragmented input. A carrier fragmented in transit must likewise be reassembled
before decode. `preserve-fragments` cannot make fragments acceptable to this
codec. CTP-emitted UDP fragments also require reassembly before encoding, so
keep application datagrams within the native MTU.

Encode reads the original IPv4 protocol. Decode requires protocol 6, valid fake
TCP geometry and ports, and at least one byte of fake TCP payload for the tag.
The tag selects native structural checks: TCP needs a complete header and a data
offset within the native span; UDP needs at least eight bytes and a declared
length fitting that span; ICMP needs at least its eight-byte base header. UDP
padding already permitted within the IP payload remains accepted. Other values
carry opaque bodies, including an empty body. A tag-only opaque carrier is valid;
a tag-only TCP, UDP or ICMP carrier is refused. A zero-valued tag is present and
valid; an absent byte is refused.

IPv4 total length must equal the buffer length. Malformed headers, IPv6,
trailing buffer bytes, oversized carriers and insufficient headroom are dropped.
Decode normally verifies visible IPv4 and fake TCP checksums, including the tag.

Every refusal preserves buffer bytes, headroom, cursor, length and checksum
intent before the node recycles it. Drop diagnostics name the reason and use
the network logger at `ERROR`. Outgoing diagnostics include packet size, maximum
native size, overhead and headroom; incoming diagnostics include packet size
and maximum carrier size. At most one diagnostic per node is emitted every five
seconds, shared by both directions, all reasons and all workers.

## Limits and Detectability

- The fake TCP framing, lack of handshake and tagged native payload
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

All examples restore private addresses explicitly and use native MTU 1479
without fake TCP options. They carry UDP because the server terminates in PTC
and `UdpConnector`, not because of a FakeTcpHeader protocol selection. Replace
documentation public addresses `192.0.2.10` and `198.51.100.10` in RawSocket and
IpOverrider. Run from the example directory with its `core.json`. The TUN
example's `route-table: "off"` leaves route selection to you: keep the public
server reachable through the ordinary interface so carriers cannot loop into
TUN. Native TCP needs suitable TCP endpoints. Broader protocols need suitable
packet endpoints at both ends, such as a direct TUN pair.

## Node Metadata

| Property | Value |
| --- | --- |
| `version` | `1` |
| node flags | `kNodeFlagNone` |
| `can_have_prev`, `can_have_next` | `true` |
| node and neighbour layers | `kNodeLayer3` |
| `required_padding_left` | `61` bytes |
| line state | none |

Build option: `INCLUDE_FAKE_TCP_HEADER_CLIENT` (default `TRUE`). Both nodes use
`FakeTcpHeaderCommon` and `ww`; neither requires the peer node or IpManipulator
module to build.

The implementation is a pure packet tunnel created with `packettunnelCreate()`.
It keeps no per-line connection state. Sequence counters belong to the node
instance and are shared across its workers.
