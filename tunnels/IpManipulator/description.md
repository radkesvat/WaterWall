# IpManipulator Node

`IpManipulator` is a packet tunnel that mutates IPv4 packets in place.

It is meant for layer-3 chains where the payload is already a raw IP packet, not a normal TCP stream line.

The current implementation provides these classes of tricks:

- protocol-number swapping
- TLS ClientHello copy (`first-sni`)
- TLS ClientHello split-route delay (`smuggle-sni`)
- TLS ClientHello overlap split (`overlap-sni`)
- TLS ClientHello SYN/FIN overlap (`synfin-sni`)
- TLS ClientHello ECH-aware transport split (`ech-sni-trick`)
- mirrored TCP FIN injection (`smuggle-fin`)
- TLS ClientHello fragmentation and shuffle (`sni-blender`)
- TCP flag bit rewriting
- source and destination port ghost tailing with transport-port remapping
- final-packet duplication

## What It Does

- Reads raw packet payload on the upstream and downstream packet paths.
- Applies enabled packet tricks in place.
- Can inject a crafted mirrored FIN/ACK packet on a dedicated upstream helper branch.
- Can hold the third upstream TLS ClientHello packet, overlap it with a crafted fake ClientHello after the fourth packet arrives, send a crafted server-side TLS packet on a helper upstream branch, emit a fake TCP SYN on the same 4-tuple, and then flush the remaining real ClientHello bytes.
- Can hold the third upstream TLS ClientHello packet, complete it with the fourth packet, then emit an enlarged real first TLS chunk, a client-looking FIN packet, a fake TCP SYN, a full crafted fake ClientHello, one valid generated TLS-looking filler packet, and the remaining real TLS bytes immediately on the normal upstream path.
- Can hold the third upstream TLS ClientHello packet, complete it with the fourth packet, locate a fake TLS ClientHello embedded inside the `encrypted_client_hello` payload, send that byte range first as an out-of-order TCP segment, and then release the original captured ClientHello packets after a delay without changing the TLS bytes.
- Optionally duplicates the final outgoing packet after all other enabled tricks.
- Marks packets for checksum recalculation when it changes protocol or TCP flags.
- Can replace one outgoing TLS ClientHello packet with multiple shuffled IP fragments.

This is a packet tunnel created with `packettunnelCreate()`, so normal stream-style `Init` and `Finish` callbacks are not part of its intended usage.

## Typical Placement

`IpManipulator` belongs in raw-packet chains, for example between packet-oriented nodes such as:

- `TunDevice`
- `WireGuardDevice`
- `RawSocket`
- other layer-3 packet tunnels

Typical use cases include:

- changing protocol numbers to evade simple filtering
- sending a crafted TLS ClientHello copy before the real ClientHello
- sending a mirrored FIN/ACK packet on a helper upstream branch without consuming the original packet
- fragmenting a TLS ClientHello to alter packet shape
- testing how a path behaves when TCP control bits are rewritten

## Configuration Example

```json
{
  "name": "ip-manipulator",
  "type": "IpManipulator",
  "settings": {
    "protoswap-tcp": 253,
    "protoswap-tcp-2": 254,
    "protoswap-udp": 252,
    "first-sni": "cover.example.net",
    "first-sni-count": 3,
    "first-sni-replay-delay": 20,
    "first-sni-final-delay": 50,
    "first-sni-ttl": 1,
    "first-sni-random-tcp-sequence": true,
    "overlap-sni": "decoy.example.net",
    "overlap-sni-delay-ms": 250,
    "overlap-sni-syn-ttl": 3,
    "synfin-sni": "decoy.example.net",
    "synfin-sni-syn-ttl": 3,
    "synfin-sni-fin-ttl": 5,
    "synfin-sni-fake-ttl": 1,
    "synfin-sni-additional-range-min": 32,
    "synfin-sni-additional-range-max": 96,
    "synfin-sni-random-syn-checksum": false,
    "synfin-sni-random-fin-checksum": false,
    "synfin-sni-random-syn-sequence": false,
    "synfin-sni-random-fin-sequence": false,
    "synfin-sni-use-rst": false,
    "crafted-server-hello-upstream-node": "server-hello-helper",
    "smuggle-fin": true,
    "fin-sni-delay-ms": 250,
    "real-fin-upstream-node": "packet-to-stream-real-fin",
    "sni-blender": true,
    "sni-blender-packets": 4,
    "packet-duplicate": 2,
    "source-port-ghost": true,
    "dest-port-ghost": true,
    "up-tcp-bit-psh": "off",
    "up-tcp-bit-ack": "toggle",
    "dw-tcp-bit-syn": "packet->ack"
  },
  "next": "next-packet-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"IpManipulator"`.

### `settings`

At least one trick must be enabled.

If none of the supported trick settings are present, tunnel creation fails with:

- `IpManipulator: no tricks are enabled, nothing to do`

## Optional `settings` Fields

### Protocol-swap settings

- `protoswap` `(integer)`
  Alias for `protoswap-tcp`.

- `protoswap-tcp` `(integer)`
  Replacement IP protocol number for TCP packets.

- `protoswap-tcp-2` `(integer)`
  Optional second replacement protocol number for TCP.

  When set, upstream and downstream TCP packets alternate between the two configured replacement numbers independently per direction.

- `protoswap-udp` `(integer)`
  Replacement IP protocol number for UDP packets.

### SNI blender settings

- `sni-blender` `(boolean)`
  Enables the TLS ClientHello fragmentation trick.

- `sni-blender-packets` `(integer)`
  Required when `sni-blender` is enabled.

  Valid range in the current implementation:
  - `1` to `16`

### Packet duplication settings

- `packet-duplicate` `(integer)`
  Optional.

  Duplicates each final outgoing packet this many times, then sends the original packet once.

  This is applied as the last step of `IpManipulator`, after all other enabled tricks have finished shaping the packet.

### first-sni settings

- `first-sni` `(string)`
  Enables the `first-sni` trick and sets the SNI that will be written into the crafted TLS ClientHello copy.

- `first-sni-ttl` `(integer)`
  Optional.

  When present, the crafted `first-sni` packet is sent with this IPv4 TTL value.

- `first-sni-count` `(integer)`
  Optional.

  Number of crafted `first-sni` packets to send before the original ClientHello.

  Defaults to `1`.

- `first-sni-replay-delay` `(integer)`
  Optional.

  Delay in milliseconds between crafted `first-sni` replays after the first one.

  Defaults to `0`.

  This value only matters when `first-sni-count` is greater than `1`.

- `first-sni-final-delay` `(integer)`
  Optional.

  Delay in milliseconds between the last crafted `first-sni` packet and the original ClientHello.

  Defaults to `0`.

- `first-sni-random-tcp-sequence` `(boolean)`
  Optional.

  When `true`, the crafted `first-sni` packet gets a fresh random TCP sequence number before it is sent.

  When `false` or omitted, the crafted `first-sni` packet keeps the original TCP sequence number.

### smuggle-sni settings

- `smuggle-sni` `(string)`
  Enables the `smuggle-sni` trick and sets the SNI that will be written into the delayed fake TLS ClientHello copy.

- `smuggle-sni-delay-ms` `(integer)`
  Optional.

  Delay in milliseconds between sending the real captured ClientHello to `real-sni-upstream-node` and sending the crafted `smuggle-sni` packet to the normal next tunnel.

  Defaults to `0`.

- `real-sni-upstream-node` `(string)`
  Required when `smuggle-sni` is enabled.

  Names another node in the same config that will receive the real captured ClientHello on the upstream path.

  In the current design this should be a dedicated branch head, not the same node as the normal `next`.

### overlap-sni settings

- `overlap-sni` `(string)`
  Enables the `overlap-sni` trick and sets the SNI that will be written into the crafted Chrome-like TLS ClientHello.

  In the current implementation, the first two upstream packets pass unchanged, the third packet is held, and the fourth packet completes the captured real TLS ClientHello. `IpManipulator` then generates its own Chrome-like TLS ClientHello, rejects the flow if the real SNI starts before the generated hello length, otherwise sends:
  - packet `Y` with the first generated-length bytes from the real captured ClientHello
  - one crafted server-side TLS packet through `crafted-server-hello-upstream-node`, built from the real downstream `SYN|ACK` header and a built-in server-hello payload
  - one fake zero-payload TCP `SYN` packet on the same 4-tuple
  - packet `X` with the generated fake ClientHello bytes on the same TCP sequence range, delayed through the overlap delay channel
  - the remaining real captured ClientHello bytes in additional delayed TCP packets

- `overlap-sni-delay-ms` `(integer)`
  Optional.

  Delay in milliseconds applied to overlap-sni packets that are sent after the fake TCP `SYN`, and to later upstream packets on the same flow while the overlap delay window remains active.

  Defaults to `0`.

  The overlap delay window duration itself is a code-level constant in the current implementation.

- `overlap-sni-syn-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the fake overlap-sni TCP `SYN` packet.

  Valid range: `0` to `255`

  When omitted, the fake TCP `SYN` keeps the original packet TTL.

- `crafted-server-hello-upstream-node` `(string)`
  Required when `overlap-sni` is enabled.

  Names another node in the same config that will receive the crafted server-side TLS packet on the upstream path.

  In the current design this should be a dedicated branch head, not the same node as the normal `next`.

`smuggle-sni` and `overlap-sni` are mutually exclusive in the current implementation.

### ech-sni-trick settings

- `ech-sni-trick` `(string)`
  Enables the `ech-sni-trick`.

  In the current architecture, this value should match `TlsClient.settings.ech-sni-trick` for the same flow. `TlsClient` is responsible for embedding the fake ClientHello inside the GREASE `encrypted_client_hello` payload, and `IpManipulator` is responsible for the transport-level out-of-order send and delayed release.

  In the current implementation, the first two upstream packets pass unchanged, the third packet is held, and the fourth packet completes the captured real TLS ClientHello. `IpManipulator` then requires:
  - a valid SNI extension
  - a valid `encrypted_client_hello` extension
  - a full fake TLS ClientHello inside the ECH payload bytes

  When those checks pass, `IpManipulator` keeps the captured ClientHello bytes unchanged and sends:
  - one out-of-order TCP packet carrying only the fake inner ClientHello bytes from the ECH payload, using the TCP sequence number that corresponds to those bytes inside the original ClientHello stream
  - after `data-shard-1-delay`, the original held upstream packet unchanged
  - after `data-shard-2-delay`, the following original upstream packet unchanged

  During both delay windows, later upstream packets on the same 4-tuple are discarded as expected retransmissions.

  In the current implementation, the crafted out-of-order `ech-sni-trick` TCP packet is sent with the `PSH` flag set so it is less likely to be buffered by middle services.

  If the out-of-order fake-inner packet would exceed `GLOBAL_MTU_SIZE`, the flow is rejected instead of being reshaped.

- `data-shard-1-delay` `(integer)`
  Optional.

  Delay in milliseconds between sending the out-of-order fake inner ClientHello segment and releasing the original held upstream packet.

  Defaults to `0`.

- `data-shard-2-delay` `(integer)`
  Optional.

  Delay in milliseconds between releasing the original held upstream packet and releasing the following original upstream packet. After this packet is released, the original ClientHello has been fully sent.

  Defaults to `0`.

`ech-sni-trick`, `smuggle-sni`, `overlap-sni`, and `synfin-sni` are mutually exclusive in the current implementation.

### synfin-sni settings

- `synfin-sni` `(string)`
  Enables the `synfin-sni` trick and sets the SNI that will be written into the crafted Chrome-like TLS ClientHello.

  In the current implementation, the first two upstream packets pass unchanged, the third packet is held, and the fourth packet completes the captured real TLS ClientHello. `IpManipulator` then generates its own Chrome-like TLS ClientHello, rejects the flow if the real SNI starts before the generated hello length, otherwise sends:
  - one real TLS data packet carrying the first `generated-length + extra-range` bytes from the captured real ClientHello on the original TCP sequence range
  - one zero-payload client-side close packet on the sequence number immediately after that first real chunk
  - one fake zero-payload TCP `SYN` packet on the same 4-tuple
  - one full crafted TLS data packet carrying the generated fake ClientHello on the original captured first-data TCP sequence range
  - one additional valid generated TLS-looking data packet whose payload length fills only that extra configured overlap range immediately after the crafted fake ClientHello on that same original sequence space
  - the remaining real captured ClientHello bytes in additional immediate TCP packets

  By default that close packet is `FIN|ACK`. When `synfin-sni-use-rst` is enabled, `IpManipulator` sends `RST|ACK` instead on the same post-fake-data sequence number.

  The fake `SYN` is rebuilt from the original captured `SYN` header template for that flow, so when checksum randomization is disabled it preserves the original SYN-style TCP header shape instead of cloning a later data packet. `IpManipulator` first sends the real first-data chunk so the destination server consumes the real beginning of the ClientHello, then emits the close packet and fake `SYN`, and only after that sends the generated fake ClientHello plus one valid generated TLS-looking filler packet on the original captured first-data sequence range. The configured extra overlap is chosen randomly per flow and is clamped so the real first-data chunk still stops before the real SNI hostname bytes.

- `synfin-sni-additional-range-min` `(integer)`
  Optional.

  Minimum number of extra real ClientHello payload bytes to append to the first real `packet_y` chunk beyond the crafted fake ClientHello length.

  When present without `synfin-sni-additional-range-max`, this value is also used as the fixed extra overlap length.

  Valid range: `0` to `65535`

  Defaults to `0`.

- `synfin-sni-additional-range-max` `(integer)`
  Optional.

  Maximum number of extra real ClientHello payload bytes to append to the first real `packet_y` chunk beyond the crafted fake ClientHello length.

  `IpManipulator` chooses one random value per flow inside the configured range, then clamps it so the enlarged real first chunk still ends before the real SNI hostname bytes and before the captured ClientHello payload ends. That same chosen extra length is then filled on the original captured sequence range by one valid generated TLS-looking data packet sent immediately after `packet_x`.

  Valid range: `0` to `65535`

  Defaults to `0`.

- `synfin-sni-syn-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the crafted `SYN` packet.

  Valid range: `0` to `255`

  When omitted, the crafted `SYN` keeps the captured packet TTL.

- `synfin-sni-fin-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the crafted close packet (`FIN|ACK` by default, `RST|ACK` when `synfin-sni-use-rst` is enabled).

  Valid range: `0` to `255`

  When omitted, the crafted `FIN` keeps the captured packet TTL.

- `synfin-sni-fake-ttl` `(integer)`
  Optional.

  When present, overrides the IPv4 TTL of the full crafted fake ClientHello packet that carries the generated `synfin-sni` payload bytes.

  This does not affect the enlarged real first TLS data packet, the generated TLS-looking filler packet after `packet_x`, or the remaining real captured ClientHello tails.

  Valid range: `0` to `255`

  When omitted, the full crafted fake ClientHello packet keeps the captured packet TTL.

- `synfin-sni-random-syn-checksum` `(boolean)`
  Optional.

  When `true`, the crafted `SYN` is sent with randomized IPv4 and TCP checksum fields instead of a recomputed valid checksum.

  Defaults to `false`.

- `synfin-sni-random-fin-checksum` `(boolean)`
  Optional.

  When `true`, the crafted close packet is sent with randomized IPv4 and TCP checksum fields instead of a recomputed valid checksum.

  Defaults to `false`.

- `synfin-sni-random-syn-sequence` `(boolean)`
  Optional.

  When `true`, the crafted `SYN` uses a fresh random TCP sequence number.

  When `false` or omitted, the crafted `SYN` uses the captured sequence pattern (`real_seq - 1`).

- `synfin-sni-random-fin-sequence` `(boolean)`
  Optional.

  When `true`, the crafted close packet uses a fresh random TCP sequence number.

  When `false` or omitted, the crafted close packet uses the TCP sequence number immediately after the fake generated ClientHello payload.

- `synfin-sni-use-rst` `(boolean)`
  Optional.

  When `true`, `IpManipulator` sends `RST|ACK` instead of `FIN|ACK` for the crafted client-side close packet that is emitted before the fake `SYN`.

  Defaults to `false`.

`0` is a real IPv4 TTL override, not a sentinel for "leave the original TTL unchanged". Omit the TTL field entirely if you want `IpManipulator` to preserve the captured packet TTL for that packet class.

`smuggle-sni`, `overlap-sni`, and `synfin-sni` are mutually exclusive in the current implementation.

### smuggle-fin settings

- `smuggle-fin` `(boolean)`
  Enables the `smuggle-fin` trick.

- `fin-sni-delay-ms` `(integer)`
  Optional.

  Delay in milliseconds between receiving the expected downstream echoed `FIN|ACK` and replaying the queued packets through the normal pipeline.

  Defaults to `0`.

- `real-fin-upstream-node` `(string)`
  Required when `smuggle-fin` is enabled.

  Names another node in the same config that will receive the crafted mirrored FIN/ACK packet on the upstream path.

  In the current design this should be a dedicated branch head, not the same node as the normal `next`.

### TCP flag rewrite settings

The current implementation supports these key prefixes:

- `up-tcp-bit-...`
- `dw-tcp-bit-...`

Supported suffixes are:

- `cwr`
- `ece`
- `urg`
- `ack`
- `psh`
- `rst`
- `syn`
- `fin`

Example keys:

- `up-tcp-bit-ack`
- `up-tcp-bit-fin`
- `dw-tcp-bit-psh`
- `dw-tcp-bit-rst`

Supported values are:

- `off`
- `on`
- `toggle`
- `flip`
- `switch`
- `packet->cwr`
- `packet->ece`
- `packet->urg`
- `packet->ack`
- `packet->psh`
- `packet->rst`
- `packet->syn`
- `packet->fin`

`flip` and `switch` are accepted as aliases for `toggle`.

- `bit-transport` `(boolean)`
  Optional.

  When `true`, directions with configured TCP-bit rewrite actions append the original TCP flags byte to the end of the TCP transport payload before rewriting flags.

  Directions with no TCP-bit rewrite actions treat that final payload byte as the transported original flags, restore the TCP flags from it, and shrink the packet by one byte.

### Port ghost settings

- `source-port-ghost` `(boolean)`
  Optional.

  When `true`, `IpManipulator` appends the original source port to the end of whole IPv4 TCP or UDP packets, then rewrites the live transport source port to a deterministic pseudo-random high port derived from the original tuple.

- `dest-port-ghost` `(boolean)`
  Optional.

  When `true`, `IpManipulator` appends the original destination port to the end of whole IPv4 TCP or UDP packets, then rewrites the live transport destination port to a deterministic pseudo-random high port derived from the original tuple.

If both are enabled, `IpManipulator` appends the source port bytes first and the destination port bytes second.

## Detailed Behavior

### Packet model

`IpManipulator` only touches packet payload callbacks:

- upstream packet payload goes through `ipmanipulatorUpStreamPayload()`
- downstream packet payload goes through `ipmanipulatorDownStreamPayload()`

Normal stream-style callbacks such as `Init` and `Finish` are intentionally not supposed to run for this tunnel.

### Protocol-number swap

The protocol-swap trick only applies to IPv4 packets.

Behavior:

- if the packet protocol is TCP and `protoswap-tcp` is enabled, the tunnel rewrites the IP protocol field to the configured protocol number
- if the packet protocol is already equal to that configured number, it rewrites it back to normal TCP
- the same idea applies to `protoswap-udp`
- the configured protocol number may be another real protocol such as `17` for UDP or `6` for TCP, so configuring
  `protoswap-tcp=17` and `protoswap-udp=6` swaps TCP and UDP protocol numbers in one pass

If `protoswap-tcp-2` is configured:

- TCP packets alternate between `protoswap-tcp` and `protoswap-tcp-2`
- upstream and downstream maintain their own toggle state

Whenever the tunnel changes the protocol field to or from a non-TCP/non-UDP protocol number, it sets
`line->recalculate_checksum = true` so a later packet writer can rebuild checksums. For direct TCP-to-UDP or
UDP-to-TCP protocol-number swaps, it refreshes only the IPv4 header checksum so the unchanged transport header is not
reinterpreted as the opposite transport protocol during checksum repair.

### SNI blender

Despite the name, this trick does not rewrite the TLS SNI string itself.

What it actually does is:

- detect an upstream IPv4 TCP packet carrying a TLS ClientHello
- split the IP payload into multiple IP fragments
- shuffle those fragments into random send order
- send the crafted fragments instead of the original packet

Important details from the current code:

- only upstream traffic is affected
- only IPv4 is supported
- only TCP packets are inspected
- only TLS ClientHello packets are fragmented
- already fragmented packets are skipped
- fragment count comes from `sni-blender-packets`
- fragment offsets are rounded to 8-byte boundaries as required by IP fragmentation

Before crafting fragments, the tunnel applies any pending checksum recalculation on the original packet, then marks each crafted packet for checksum recalculation before forwarding.

### first-sni

This trick is upstream-only and only applies to IPv4 TCP packets that begin with a TLS ClientHello carrying an SNI extension.

Behavior:

- detect an upstream TLS ClientHello
- parse the first host-name entry in the TLS server-name extension
- clone the packet and replace only the copied packet's SNI with `first-sni`
- send the modified copy first
- if `first-sni-ttl` is set, update the crafted packet TTL to that value
- if `first-sni-random-tcp-sequence` is `true`, randomize the crafted packet's TCP sequence number
- recompute the crafted packet checksum before send
- then forward the original packet using the original `line->recalculate_checksum` intent
- when replay or final delays are configured, `IpManipulator` keeps a short shared flow record for that TCP 4-tuple and delays later upstream packets on the same flow so they cannot overtake the held original ClientHello

If `first-sni` is longer or shorter than the original SNI, the copied packet updates the relevant TLS and IPv4 length fields.

If the ClientHello contains a TLS 1.3 `pre_shared_key` extension with PSK binders and the configured `first-sni` would actually change the SNI bytes, the trick skips crafting the fake packet and leaves the original packet path alone. `IpManipulator` does not own the PSK secret needed to recompute valid binders.

### smuggle-sni

This trick is upstream-only and only applies to IPv4 TCP packets that begin with a TLS ClientHello carrying an SNI extension.

Behavior:

- detect an upstream TLS ClientHello
- clone the packet and replace only the copied packet's SNI with `smuggle-sni`
- send the real captured ClientHello through `real-sni-upstream-node` immediately
- wait `smuggle-sni-delay-ms`
- send the modified `smuggle-sni` copy through the normal top-level `next` tunnel
- leave every non-ClientHello packet on the normal path unchanged

`smuggle-sni` does not keep per-flow connection state. It only sends one immediate real ClientHello to `real-sni-upstream-node` and schedules one delayed crafted `smuggle-sni` copy on the normal branch.

If the ClientHello contains a TLS 1.3 `pre_shared_key` extension with PSK binders and the configured `smuggle-sni` would actually change the SNI bytes, the trick skips crafting the fake packet and leaves the original packet on the normal path. `IpManipulator` does not have the PSK secret required to recompute valid binders.

### smuggle-fin

This trick is upstream-only and only applies to whole IPv4 TCP packets that already carry ACK and transport payload.

Behavior:

- clone the original IPv4 and TCP headers into a header-only packet
- swap the copied packet's source and destination IPv4 addresses
- swap the copied packet's TCP source and destination ports
- turn the copied packet into a pure `FIN|ACK` packet with no transport payload
- mirror the TCP sequence and acknowledgement numbers from the original packet so the crafted packet looks like the reverse direction
- send the crafted packet immediately through `real-fin-upstream-node`
- pause this worker packet path inside `IpManipulator`
- queue later upstream and downstream packets on that worker instead of forwarding them immediately
- ignore the first downstream packet that exactly matches the crafted `FIN|ACK`
- wait `fin-sni-delay-ms`
- replay the queued packets in arrival order through the normal pipeline
- keep the remembered flow in the internal table after that success so the expected echoed `FIN|ACK` is not treated as a real connection-closing FIN event for this trick

Packets without TCP payload, packets that are already `SYN`, `FIN`, or `RST`, and non-TCP or fragmented IPv4 packets are left alone.

### TCP flag rewriting

The TCP-bit trick only applies to valid IPv4 TCP packets.

For each configured bit action, the tunnel can:

- force the bit off
- force the bit on
- toggle it
- copy the value of another TCP flag from the same packet

If any flag changes:

- the TCP flags byte is rewritten
- `line->recalculate_checksum` is set to `true`

This happens independently on upstream and downstream using the `up-...` and `dw-...` setting families.

If `bit-transport` is enabled:

- rewrite directions append one extra payload byte carrying the original TCP flags before applying any configured TCP-bit actions
- restore directions copy that byte back into the TCP flags field and reduce the IPv4 packet length by one byte
- fragmented IPv4 packets are skipped so the tunnel only operates on whole TCP packets with a real TCP header and transport payload

### Port ghost tailing

The port-ghost trick only applies to whole IPv4 TCP or UDP packets.

When `source-port-ghost` and/or `dest-port-ghost` are enabled:

- the selected original TCP or UDP port bytes are appended at the end of the transport packet payload
- the matching live TCP or UDP port fields are rewritten to deterministic pseudo-random high ports derived from the original tuple
- downstream packets that still carry those transported port bytes restore the original live port fields and shrink the packet back to its original length
- IPv4 total length is increased to cover the appended ghost bytes
- UDP length is also increased when the packet is UDP
- `line->recalculate_checksum` is set so a later packet writer rebuilds checksums
- fragmented IPv4 packets are skipped

## Notes And Caveats

- This tunnel is for raw packet chains, not normal byte-stream chains.
- Only IPv4 packets are modified by the current implementation.
- `first-sni` is upstream-only and rewrites the first TLS host-name entry in the crafted copy.
- `smuggle-sni` is upstream-only and sends the real matching ClientHello immediately to `real-sni-upstream-node`, then delays the crafted `smuggle-sni` copy to the normal `next` branch.
- `smuggle-fin` is upstream-only and injects a crafted mirrored FIN/ACK packet to `real-fin-upstream-node`, then temporarily queues later packets on that worker until the expected downstream echo is seen and the optional `fin-sni-delay-ms` window expires.
- `sni-blender` is upstream-only. The downstream half of that trick is currently a no-op.
- The tunnel relies on later packet-writing code to honor `line->recalculate_checksum` and rebuild packet checksums.
- `sni-blender-packets` is required when `sni-blender` is enabled.
- `first-sni-random-tcp-sequence` affects only the crafted `first-sni` copy, not the original packet.
- The struct contains `trick_sni_blender_packets_delay_max`, but current JSON parsing does not expose or use it.
