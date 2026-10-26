<!--
Documentation version: 158
Sync note: Keep this file aligned with WaterWall-Docs/docs/02-noderefs/PingServer.mdx.
-->

# PingServer Node

`PingServer` is the server-side endpoint of Ping wire v2. It is an IPv4-only,
pure packet tunnel with no line state and one bounded synchronized Echo
correlation and replay tracker for the whole node.

After decoding an Echo Request, inner packets are forwarded upstream on
the arrival worker. Correlation, replay checks and any generated Echo Reply also
stay on that worker; the shared tracker does not require transport-flow affinity.
Inner fragments are forwarded immediately with their bytes and boundaries intact,
without waiting for the leading fragment. A later stateful consumer establishes
its own flow ownership. Unrelated or unmatched ICMP retains its packet bytes.

Use it opposite `PingClient`:

```text
TunDevice -> PingClient -> RawSocket
RawSocket -> PingServer -> TunDevice
```

## Echo v2 Model and Direction

Every data packet is a fresh type-8 Echo Request. With `send-replies: true`,
its peer first sends a type-0 Echo Reply with the identifier, sequence, and ICMP
data copied exactly. The default is `false`, which skips reply allocation,
copying, and transmission. Each endpoint chooses this setting independently;
request tracking and replay suppression remain active, and incoming correlated
Echo Replies are consumed as acknowledgements regardless of the local setting.
Data delivery does not wait for a reply. Opposite-direction application data
uses a separate new Echo Request.

| Event | Action |
| --- | --- |
| upstream peer Echo Request | If `send-replies` is true, build/send its Echo Reply downstream; decapsulate the request upstream once. |
| upstream matching Echo Reply | Consume it as an acknowledgement. |
| downstream plain IPv4 packet | Build an Echo Request and forward downstream. |

This preserves callback direction: decoded upstream data uses
`tunnelNextUpStreamPayload()`, while optional generated replies and outgoing
downstream requests use `tunnelPrevDownStreamPayload()`.

## Configuration

```json
{
  "name": "ping-server",
  "type": "PingServer",
  "settings": {
    "local-ipv4": "203.0.113.20",
    "peer-ipv4": "198.51.100.10",
    "send-replies": false,
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
| `send-replies` | no | `false` | Boolean. Send exact Echo Replies for received peer requests when true; false or omission skips reply generation. |
| `identifier` | no | `"random"` | Local request-session identifier. Integer `0..65535` gives a deterministic override. |
| `sequence-start` | no | `1` | First locally emitted request sequence. Range: `0..65535`. |
| `ttl` | no | `64` | TTL for locally generated packets. Integer `0..255`. |
| `tos` | no | `0` | TOS for local requests. Integer `0..255`; replies copy the incoming request TOS. |

The paired client must reverse `local-ipv4` and `peer-ipv4`. Identifiers are
local-session values, not a shared peer setting.

## Wire, Validation, and Limits

The only carrier is a fresh IPv4 header plus ICMP Echo header plus one complete
inner IPv4 packet. Requests have type `8`, code `0`, DF set, and IPv4 ID `0`.
When `send-replies` is true, replies have type `0`, code `0`, reverse addresses,
clear DF/fragmentation, and mirror request identifier, sequence, payload length,
and payload bytes exactly.

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
  delivers its inner packet only once and is replied to again only when
  `send-replies` is true.

The node advertises `28` bytes of left padding. It does not perform PMTU
discovery, fragmentation, or TCP MSS adjustment. The resulting carrier limit is
`1500` bytes.

Packet rejection diagnostics use the network logger at `ERROR` level and
identify the specific validation, checksum, size, headroom, or tracking failure.
Each drop message includes the packet length, maximum inner/carrier lengths,
wrapper overhead, and available/required left headroom, all in bytes. The
five-second log gate is shared by all failure reasons, directions, and workers
of each node, so it does not emit one message per rejected packet.

## Breaking Migration From Ping Wire v1

Ping wire v2 accepts only `local-ipv4`, `peer-ipv4`, `send-replies`, `identifier`,
`sequence-start`, `ttl`, and `tos`. All v1 strategy names and aliases, header
reuse, ICMP-only mode, protocol swapping, identifier checking, XOR, roundup,
and `ipv4-id-start` are rejected with a migration error.

Replace v1 `source`/`dest` with required `local-ipv4`/`peer-ipv4`, reverse them
on PingClient, and upgrade both peers together. Version 2 is intentionally not
wire-compatible with the removed formats.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| `version` | `2` |
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` |
| `layer_group_prev_node` | `kNodeLayer3` |
| `layer_group_next_node` | `kNodeLayer3` |
| `required_padding_left` | `28` bytes |
| line state | none |
