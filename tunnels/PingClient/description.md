<!--
Documentation version: 154
Sync note: Keep this file aligned with WaterWall-Docs/docs/02-noderefs/PingClient.mdx.
-->

# PingClient Node

`PingClient` is the client-side endpoint of Ping wire v2, an IPv4-only packet
tunnel that carries one complete inner IPv4 packet in one real ICMP Echo
Request. It is a pure packet tunnel (`packettunnelCreate()`), has no line
state, and uses one bounded synchronized correlation and replay tracker for the
whole node.

Use it with `PingServer` in this order:

```text
TunDevice -> PingClient -> RawSocket
RawSocket -> PingServer -> TunDevice
```

## Echo v2 Model

Ping wire v2 has two independent Echo sessions, one for data originated by
each endpoint. It never puts new application data into an Echo Reply.

```text
client data: PingClient -- Echo Request(data) --> PingServer
             PingClient <-- Echo Reply(same bytes) -- PingServer

server data: PingClient <-- Echo Request(data) -- PingServer
             PingClient -- Echo Reply(same bytes) --> PingServer
```

An Echo Request is delivered once after the peer has built its reply. The
request originator matches and consumes that Echo Reply as a wire
acknowledgement, so echoed inner bytes are never delivered twice.

For PingClient the callback behavior is:

| Event | Action |
| --- | --- |
| upstream plain IPv4 packet | Build an Echo Request and forward upstream. |
| downstream peer Echo Request | Build/send its Echo Reply upstream, then decapsulate the original request downstream. |
| downstream matching Echo Reply | Consume it as an acknowledgement. |

## Configuration

```json
{
  "name": "ping-client",
  "type": "PingClient",
  "settings": {
    "local-ipv4": "198.51.100.10",
    "peer-ipv4": "203.0.113.20",
    "identifier": "random",
    "sequence-start": 1,
    "ttl": 64,
    "tos": 0
  },
  "next": "raw-out"
}
```

| Setting | Required | Default | Meaning |
| --- | --- | --- | --- |
| `local-ipv4` | yes | — | Source address for locally originated requests and replies. |
| `peer-ipv4` | yes | — | Destination for local requests and expected source of peer carrier traffic. |
| `identifier` | no | `"random"` | Local request-session identifier. An integer `0..65535` is a deterministic override. The random default is nonzero and stable for this node lifetime. |
| `sequence-start` | no | `1` | First sequence number placed on the wire. Range: `0..65535`; wrap is valid. |
| `ttl` | no | `64` | TTL for locally generated packets. |
| `tos` | no | `0` | TOS for locally generated requests. Replies copy the peer request TOS. |

PingClient and PingServer intentionally have separate local identifiers. A
reply always mirrors the identifier and sequence of the request it answers;
it never uses the responder's configured identifier.

## Wire Rules

Every local data packet becomes exactly:

```text
20-byte IPv4 header -> 8-byte ICMP Echo header -> complete inner IPv4 packet
```

- locally generated requests use type `8`, code `0`, configured source/destination,
  configured TOS/TTL, DF set, and IPv4 ID `0`;
- the request identifier is local and the sequence advances once per request;
- replies use type `0`, code `0`, reverse addresses, copy request identifier,
  sequence, ICMP payload length, and every payload byte;
- generated replies copy request TOS, use local configured TTL, clear DF and
  fragmentation bits, and use a securely seeded tuple-scoped IPv4-ID
  approximation. It is Linux-like, not a copy of host-global Linux kernel state.

The inner packet is not encrypted. Correct Echo headers reduce obvious protocol
mistakes; they do not make high-rate arbitrary tunnel traffic indistinguishable
from an interactive `ping` process.

## Validation, Limits, and Correlation

- Input must be one complete IPv4 packet whose buffer length equals its IPv4
  total length. IPv6, malformed input, and inner packets larger than `1472`
  bytes are dropped rather than forwarded outside the carrier.
- Valid inner IPv4 fragments are supported. The outer carrier itself must be
  unfragmented and exactly `20 + 8 + inner length` bytes.
- Incoming carrier traffic requires matching peer/local addresses, valid IPv4
  and ICMP checksums, Echo type/code, and a complete inner IPv4 packet for a
  request. Invalid addressed carrier traffic is dropped at a bounded log rate.
- Structurally valid traffic that is unrelated to the configured carrier tuple
  passes through in its original callback direction.
- One node-wide tracker has a 1024-entry outstanding ring and a 1024-entry
  replay ring. Device worker affinity is not correlation identity: a reply or
  duplicate request may arrive on a different packet-line WID and still match.
  An old outstanding acknowledgement may be overwritten as packet loss;
  duplicate peer requests receive another reply but deliver their inner packet
  only once.

The node advertises `28` bytes of left padding and accepts at most `1472` bytes
of inner IPv4 data, producing a maximum `1500`-byte carrier packet. It does not
fragment traffic, discover PMTU, or adjust TCP MSS.

## Breaking Migration From Ping Wire v1

Only the settings listed above are accepted. Ping v1 strategies and settings
are rejected with a migration error, including:

- `strategy`, all `wrap-*`/`warp-*` values, and ICMP-only/protocol-swap modes;
- `source`, `dest`, `swap-protocol`, `swap-identifier`, and `check-identifier`;
- `ipv4-id-start`, `xor-byte`, `roundup-size`, and `roundup`.

Replace `source`/`dest` with required `local-ipv4`/`peer-ipv4`; reverse those
addresses on the paired server. Upgrade both peers together: Ping wire v2 is
not wire-compatible with the removed formats.

## Node Metadata

| Property | Value |
| --- | --- |
| version | `2` |
| layer | `kNodeLayer3` on both sides |
| required left padding | `28` bytes |
| line state | none |
