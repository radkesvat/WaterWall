<!--
Documentation version: 161
Sync note: Keep aligned with WaterWall-Docs/docs/02-noderefs/PingServer.mdx and its Persian translation.
-->

# PingServer Node

## Overview

`PingServer` is a pure IPv4 packet transform paired with `PingClient`.

Only complete native **IPv4** packets are supported. At the 1,500-byte
carrier ceiling, the native packet limit is 1,491 bytes,
including IP and transport headers. Account for any other chain overhead and
smaller path MTUs. Reassemble fragments at the packet adapters before these nodes;
keep the real peer reachable outside the TUN route.

## Typical placement

Both endpoints carry their local data as new ICMP Echo Requests.
Optional Echo Replies acknowledge requests; reverse data uses independent new
requests and never waits for an acknowledgement.

### Deployment scenarios

```text
client: TunDevice -> PingClient -> IpOverrider -> RawSocket
server: RawSocket -> IpOverrider -> PingServer -> TunDevice
```

Users own address rewriting/restoration and routing. Capture the peer's network
address and protocol `1` with RawSocket. With IpOverrider between capture and
the decoder, choose `"opaque-flow-mode": "peer"` explicitly because `auto` only
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
  "name": "pingserver",
  "type": "PingServer",
  "settings": {"identifier": "random", "sequence-start": 1, "send-replies": false},
  "next": "next-node"
}
```

## Configuration

### Settings

Settings may be omitted or an empty object.


| Setting | Default | Meaning |
| --- | --- | --- |
| `identifier` | `"random"` | Stable random nonzero local identifier, or integer `0..65535`. Replies mirror the request identifier. |
| `sequence-start` | `1` | Integer `0..65535`; sequence wraps normally. |
| `send-replies` | `false` | Boolean enabling exact replies to received requests. |

Only these settings are accepted. `local-ipv4`, `peer-ipv4`, `ttl` and `tos`
are rejected as unknown settings. Data addresses and header policy belong to
the surrounding chain.

## Usage and troubleshooting

### MTU and reassembly

The user is responsible for configuring a native MTU that leaves room for all
chain overhead and the actual network path. Ordinary Ping and direct-mode Ping6 add nine bytes and drop
native packets exceeding the 1,500-byte carrier ceiling after encoding. They do
not discover or negotiate MTU, adjust MSS, segment, or fragment packets. Both
entry points reject IP fragments; configure packet adapters to reassemble
fragments before these nodes. Setting `preserve-fragments` does not make fragments
acceptable.

At this ceiling, 1,491 bytes is the maximum **complete native IPv4 packet**,
including its IP and transport headers. A 1,492-byte native packet is dropped.
Configure TunDevice `device-mtu`, applicable ConnectionToPackets and
PacketsToConnection `mtu`, and core `misc.mtu` for all chain overhead in both
directions. A larger core/device MTU never waives the carrier ceiling. A smaller
network path requires a smaller native MTU. Keep the real peer reachable outside
the TUN route. Set `"fragment-policy": "reassemble"` on packet adapters.

MF or nonzero fragment offset is refused at encode and decode before native
parsing, checksum repair or mutation, including with repair intent. DF alone
is accepted and preserved. Reassemble native fragments before encoding and
transit-fragmented carriers before decoding.

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
carrier:[same IPv4, protocol=1][Echo Request 8][native body B][P 1]
```

The saved protocol is the **last byte of the declared IP packet**, inside the
Echo checksum coverage. There is exactly one IPv4 header. Encoding adds nine
bytes; decoding removes the Echo header and final byte. IPv4 options are supported.
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

### Directions, replies and tracking

| Input to PingServer | Action |
| --- | --- |
| downstream native packet | Emit a fresh type-8, code-0 request toward `prev`. |
| upstream request | Optionally send an independent reply toward `prev`, then deliver the decoded original toward `next` once. |
| upstream matching reply | Consume the reply. |
| upstream valid unmatched reply | Forward the complete carrier unchanged toward `next`. |

Both endpoints always encode local data as new requests. `send-replies` is
independent at each endpoint and defaults to false. When enabled, the receiver
clones the validated request before decapsulation. A generated type-0, code-0
reply preserves identifier, sequence and exact normalized Echo payload including
the trailer; it reverses received IPv4 addresses, copies TOS, uses TTL 64,
generates an IPv4 ID and clears fragmentation flags. Data delivery never waits
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
| `version` | `2` |
| flags | `kNodeFlagNone` |
| `can_have_prev` / `can_have_next` | `true` / `true` |
| node / previous / next layer | `kNodeLayer3` |
| `required_padding_left` | `9` bytes |
| line state | none |

Lifecycle Init/Est/Finish/Pause/Resume callbacks retain same-direction forwarding.
These nodes create or destroy no normal lines, never destroy packet lines, and
start no private readers or timers.
