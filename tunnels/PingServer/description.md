<!--
Documentation version: 154
Sync note: Keep this file aligned with WaterWall-Docs/docs/02-noderefs/PingServer.mdx.
-->

# PingServer Node

`PingServer` is the server-side endpoint of Ping wire v2. It is an IPv4-only,
pure packet tunnel with no line state and one bounded synchronized Echo
correlation and replay tracker for the whole node.

Use it opposite `PingClient`:

```text
TunDevice -> PingClient -> RawSocket
RawSocket -> PingServer -> TunDevice
```

## Echo v2 Model and Direction

Every data packet is a fresh type-8 Echo Request. Its peer immediately sends a
type-0 Echo Reply with the identifier, sequence, and ICMP data copied exactly.
The reply is an acknowledgement only; opposite-direction application data uses
a separate new Echo Request.

| Event | Action |
| --- | --- |
| upstream peer Echo Request | Build/send its Echo Reply downstream, then decapsulate the request upstream. |
| upstream matching Echo Reply | Consume it as an acknowledgement. |
| downstream plain IPv4 packet | Build an Echo Request and forward downstream. |

This preserves callback direction: decoded upstream data uses
`tunnelNextUpStreamPayload()`, while generated replies and outgoing downstream
requests use `tunnelPrevDownStreamPayload()`.

## Configuration

```json
{
  "name": "ping-server",
  "type": "PingServer",
  "settings": {
    "local-ipv4": "203.0.113.20",
    "peer-ipv4": "198.51.100.10",
    "identifier": "random",
    "sequence-start": 1,
    "ttl": 64,
    "tos": 0
  },
  "next": "tun-in"
}
```

| Setting | Required | Default | Meaning |
| --- | --- | --- | --- |
| `local-ipv4` | yes | — | Source address for locally originated requests and replies. |
| `peer-ipv4` | yes | — | Destination for local requests and expected source of peer carrier traffic. |
| `identifier` | no | `"random"` | Local request-session identifier. Integer `0..65535` gives a deterministic override. |
| `sequence-start` | no | `1` | First locally emitted request sequence. Range: `0..65535`. |
| `ttl` | no | `64` | TTL for locally generated packets. |
| `tos` | no | `0` | TOS for local requests. Replies copy the incoming request TOS. |

The paired client must reverse `local-ipv4` and `peer-ipv4`. Identifiers are
local-session values, not a shared peer setting.

## Wire, Validation, and Limits

The only carrier is a fresh IPv4 header plus ICMP Echo header plus one complete
inner IPv4 packet. Requests have type `8`, code `0`, DF set, and IPv4 ID `0`.
Replies have type `0`, code `0`, reverse addresses, clear DF/fragmentation, and
mirror request identifier, sequence, payload length, and payload bytes exactly.

Replies use a securely seeded, tuple-scoped IPv4-ID approximation with bounded
idle perturbation. It models observable mainline Linux behavior, but cannot
model unrelated packets that share a real host kernel's ID state.

- A local input must be an exact IPv4 packet no larger than `1472` bytes;
  malformed/non-IPv4/oversized data is dropped rather than leaked outside the
  carrier.
- Valid inner IPv4 fragments are accepted. Outer carrier fragmentation,
  malformed lengths, or invalid IPv4/ICMP checksums are rejected.
- Carrier classification requires expected peer/local addresses. Structurally
  valid unrelated IPv4 traffic continues in the same direction.
- Node-wide 1024-entry outstanding and replay rings bound memory. Device worker
  affinity is not correlation identity, so replies and duplicate requests match
  even when their callbacks use a different packet-line WID. A replayed request
  is replied to again but its inner packet is delivered only once.

The node advertises `28` bytes of left padding. It does not perform PMTU
discovery, fragmentation, or TCP MSS adjustment. The resulting carrier limit is
`1500` bytes.

## Breaking Migration From Ping Wire v1

Ping wire v2 accepts only `local-ipv4`, `peer-ipv4`, `identifier`,
`sequence-start`, `ttl`, and `tos`. All v1 strategy names and aliases, header
reuse, ICMP-only mode, protocol swapping, identifier checking, XOR, roundup,
and `ipv4-id-start` are rejected with a migration error.

Replace v1 `source`/`dest` with required `local-ipv4`/`peer-ipv4`, reverse them
on PingClient, and upgrade both peers together. Version 2 is intentionally not
wire-compatible with the removed formats.

## Node Metadata

| Property | Value |
| --- | --- |
| version | `2` |
| layer | `kNodeLayer3` on both sides |
| required left padding | `28` bytes |
| line state | none |
