<!--
Documentation version: 4
Sync note: Keep aligned with WaterWall-Docs/docs/02-noderefs/Ping6Client.mdx and its Persian translation.
-->

# Ping6Client Node

## Overview

`Ping6Client` is a pure IPv4 packet transform paired with `Ping6Server`.

Only complete native **IPv4** packets are supported. At the 1,500-byte
carrier ceiling, the native packet limit is 1,491 bytes in direct mode or 1,451 bytes in `ipv6-in-ipv4` mode,
including IP and transport headers. Account for any other chain overhead and
smaller path MTUs. Reassemble fragments at the packet adapters before these nodes;
keep the real peer reachable outside the TUN route.

## Typical placement

Both endpoints carry their local data as new ICMPv6-style Echo Requests over IPv4.
Optional Echo Replies acknowledge requests; reverse data uses independent new
requests and never waits for an acknowledgement.

### Deployment scenarios

```text
client: TunDevice -> Ping6Client -> IpOverrider -> RawSocket
server: RawSocket -> IpOverrider -> Ping6Server -> TunDevice
```

Users own address rewriting/restoration and routing. Capture the peer's network
address and protocol `58` for direct mode or `41` for `ipv6-in-ipv4` with
RawSocket. With IpOverrider between capture and the decoder, choose `"opaque-flow-mode": "peer"` explicitly because `auto` only
recognizes a directly adjacent decoder. These are packet chains; ordinary
UdpListener/UdpConnector normal-line compositions are unsupported.

The trailer is not a signature. Ordinary Echo payloads can satisfy this layout,
especially for opaque native protocols. The chain/capture configuration must
select a dedicated carrier stream, with one logical carrier peer per node.
There is no encryption, peer authentication or automatic distinction from
ordinary pings. Valid unrelated IPv4 protocols pass through unchanged, preserving
pending checksum intent, subject to fragment rejection below.


## Minimal practical example

This is a **node fragment** for the packet chain above. `next-node` is a
placeholder for the next configured node; the packet adapters, peer, capture,
address restoration, routes, and MTU must also be configured.

```json
{
  "name": "ping6client",
  "type": "Ping6Client",
  "settings": {"identifier": "random", "sequence-start": 1, "send-replies": false},
  "next": "next-node"
}
```

This fragment uses the default `direct` mode. Both peers must select the same
mode; `ipv6-in-ipv4` additionally requires mirrored inner IPv6 endpoints and the
address restrictions described under [Packet representation](#packet-representation).

## Configuration

### Settings

Settings may be omitted or an empty object.


| Setting | Default | Meaning |
| --- | --- | --- |
| `identifier` | `"random"` | Stable random nonzero local identifier, or integer `0..65535`. Replies mirror the request identifier. |
| `sequence-start` | `1` | Integer `0..65535`; sequence wraps normally. |
| `send-replies` | `false` | Boolean enabling exact replies to received requests. |
| `mode` | `"direct"` | Exact string `direct` or `ipv6-in-ipv4`; immutable for the instance. |
| `local-ipv6` | required only in `ipv6-in-ipv4` | Bare local inner IPv6 endpoint; forbidden in direct mode. |
| `peer-ipv6` | required only in `ipv6-in-ipv4` | Bare peer inner IPv6 endpoint; forbidden in direct mode. |

Only these settings are accepted. `local-ipv4`, `peer-ipv4`, `ttl` and `tos`
are rejected as unknown settings. Data addresses and header policy belong to
the surrounding chain.

## Usage and troubleshooting

### MTU and reassembly

The user is responsible for configuring a native MTU that leaves room for all
chain overhead and the actual network path. Direct Ping6 adds nine bytes and
IPv6-in-IPv4 Ping6 adds 49; both drop native packets exceeding the 1,500-byte
carrier ceiling after encoding. They do not discover or negotiate MTU, adjust MSS, segment, or fragment packets. Both
entry points reject IP fragments; configure packet adapters to reassemble
fragments before these nodes. Setting `preserve-fragments` does not make fragments
acceptable.

At this ceiling, the maximum **complete native IPv4 packet**, including its IP
and transport headers, is 1,491 bytes in direct mode or 1,451 in IPv6-in-IPv4 mode.
A 1,492-byte direct or 1,452-byte IPv6-in-IPv4 native packet is dropped.
Configure TunDevice `device-mtu`, applicable ConnectionToPackets and
PacketsToConnection `mtu`, and core `misc.mtu` for all chain overhead in both
directions. A larger core/device MTU never waives the carrier ceiling. A smaller
network path requires a smaller native MTU. Keep the real peer reachable outside
the TUN route. Set `"fragment-policy": "reassemble"` on packet adapters.

MF or nonzero fragment offset is refused at encode and decode before native
parsing, checksum repair or mutation, including with repair intent. DF alone
is accepted and preserved. Reassemble native fragments before encoding and
transit-fragmented outer IPv4 carriers before decoding. Inner IPv6 Fragment
headers are rejected rather than reassembled here; these nodes add no reassembly,
retries, PMTU negotiation or automatic core/device MTU changes.

Drops use `ERROR` diagnostics naming geometry, fragmentation/reassembly,
checksum, size, headroom or tracking failures. Messages include packet length,
native/carrier limits, overhead and available/required headroom. One shared
five-second rate limiter covers all reasons, directions and workers per node.

## Advanced behavior

### Packet representation

For an actual IPv4 header length `H = 20..60`, original protocol `P = 0..255`
and native body `B`, including any native transport header:

```text
native: [existing IPv4, protocol=P ][native body B]
direct: [same IPv4, protocol=58][Echo Request 8][native body B][P 1]
6in4:   [same IPv4, protocol=41][IPv6 40, Next Header=58][Echo Request 8][native body B][P 1]
```

The saved protocol is the **last byte of the declared IP packet**, inside the
Echo checksum coverage. There is exactly one IPv4 header. `mode` defaults to
`direct`, adding nine bytes; `ipv6-in-ipv4` adds 49 bytes including one IPv6 base
header. Decoding removes the selected framing and final byte. Both modes accept
and deliver complete native **IPv4** packets. IPv4 options are supported.
The buffer length must equal IPv4 total length. TCP data offset, UDP datagram
length and generic ICMP geometry are checked against the native span, excluding
framing. UDP padding remains accepted; other protocols are opaque and may have
an empty body. A present protocol byte of zero is valid.

The transform preserves current source/destination, options, ID, DF, TTL and
TOS/DSCP/ECN locally. Only protocol, total length and IPv4 checksum change as
framing. Transit changes such as TTL decrement, option processing and deliberate
address rewrites remain visible after decode; no saved original header exists.

For TCP/UDP, encoding incrementally changes the native checksum's address
contributions from actual addresses to zero/zero. Decode restores contributions
from zero/zero to the current IPv4 addresses. Disabled UDP checksum zero and
invalid native checksum residuals survive unless native repair was explicitly
requested before encoding. Carrier repair affects only visible IPv4/Echo
checksums and never repairs hidden native corruption. ICMP and opaque bodies
receive no address normalization. Protocols that protect addresses or other IP
fields need those fields preserved/restored or a protocol-aware transform.

Direct mode uses fixed `::`/`::` pseudo-header checksum inputs with Next Header
58 and complete Echo message length, including its header and trailer. It forbids
both IPv6 address settings, even if null or `::`.

In `ipv6-in-ipv4` mode, `local-ipv6` and `peer-ipv6` are required actual inner
source/destination addresses, mirrored at the peer. Strict bare IPv6 text accepts
ULA, global and link-local unicast, including valid compressed IPv4 tails.
Unspecified `::`, loopback `::1`, multicast `ff00::/8` and IPv4-mapped
`::ffff:0:0/96` endpoints are rejected, as are brackets, zones, prefixes, malformed
encoding and embedded NULs. No public IPv6 connection, OS address assignment or
shared subnet is required; inner addresses are endpoint identifiers, not authentication.

Generated inner IPv6 has version 6, Traffic Class copied from native TOS, Flow
Label zero, Next Header 58 and Hop Limit 64. Payload Length is the full Echo
message length. Incoming source/destination must equal configured peer/local;
version, immediate Next Header and exact inner/outer length agreement are checked
before repair or tracking. Extension headers, including IPv6 Fragment, and
jumbograms are outside this fixed envelope. Legal received Traffic Class, Flow
Label and Hop Limit changes, including zero Hop Limit, are accepted. ICMPv6 uses
the actual inner wire addresses and Echo length in its pseudo-header. IPv6 has no
header checksum. Other outer protocols pass as unrelated traffic, with no automatic
mode detection. Both peers must explicitly select the same mode.

This is a fixed IPv6-in-IPv4 carrier using WaterWall's body/trailer convention,
not a general IPv6 router or complete RFC 4213 implementation. Ordinary ping tools
do not automatically recover native packets from it.

### Directions, replies and tracking

| Input to Ping6Client | Action |
| --- | --- |
| upstream native packet | Emit a fresh type-128, code-0 request toward `next`. |
| downstream request | Optionally send an independent reply toward `next`, then deliver the decoded original toward `prev` once. |
| downstream matching reply | Consume the reply. |
| downstream valid unmatched reply | Forward the complete carrier unchanged toward `prev`. |

Both endpoints always encode local data as new requests. `send-replies` is
independent at each endpoint and defaults to false. When enabled, the receiver
clones the validated request before decapsulation. A generated type-129, code-0
reply preserves identifier, sequence and exact normalized Echo payload including
the trailer; it reverses received IPv4 addresses, copies TOS, uses TTL 64,
generates an IPv4 ID and clears fragmentation flags. In the new mode it also
reverses the received inner IPv6 pair, copies **inner** Traffic Class independently
of outer TOS, resets Flow Label to zero and Hop Limit to 64, and retains Echo length. Data delivery never waits
for a reply. The original and reply have independent buffer ownership.

Each node has synchronized 1,024-entry outstanding and replay rings. Matching
uses type/code, identifier, sequence, payload length and a locally keyed digest
of the exact native body plus trailer; addresses and worker IDs are excluded.
Matching replies clear the outstanding entry. Valid unmatched replies can have
arbitrary or empty payloads and are never decoded as native packets. Requests
are marked before outward callbacks, including reentrant callbacks. Remembered
duplicates deliver data once and may receive another optional reply. Bounded
replacement can allow an evicted old identity to be accepted again. These rings
are bookkeeping, not authentication, retransmission or reliability.

## Implementation details

### Worker and line behavior

The node uses
chain-owned worker packet lines, zero per-line state and bounded node-wide Echo
correlation. Decoding, replay checks and optional replies stay on the arrival
worker; a later stateful consumer establishes its own transport-flow affinity.

### Node metadata

| Property | Value |
| --- | --- |
| `version` | `1` |
| flags | `kNodeFlagNone` |
| `can_have_prev` / `can_have_next` | `true` / `true` |
| node / previous / next layer | `kNodeLayer3` |
| `required_padding_left` | `9` bytes (direct) or `49` (ipv6-in-ipv4), selected during construction |
| line state | none |

Lifecycle Init/Est/Finish/Pause/Resume callbacks retain same-direction forwarding.
These nodes create or destroy no normal lines, never destroy packet lines, and
start no private readers or timers.
