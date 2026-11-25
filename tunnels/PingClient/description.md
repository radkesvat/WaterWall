<!--
Documentation version: 161
Sync note: Keep aligned with WaterWall-Docs/docs/02-noderefs/PingClient.mdx and its Persian translation.
-->

# PingClient Node

## Overview

`PingClient` is a layer-3 transform paired with `PingServer`. Each peer
sends independent ICMPv4 data packets using the existing IPv4 header. The
receiver accepts the peer's independently configured ICMP type and code.

## Typical placement

### Deployment scenarios

```text
client: TunDevice -> PingClient -> RawSocket
server: RawSocket -> PingServer -> TunDevice
```

A direct pair uses the source and destination already on the packet. For
different native and carrier addresses, put `IpOverrider` between Ping and
RawSocket on each side. Configure both directions to write the appropriate
native or carrier address pair. Keep the carrier peer reachable through the
physical network.

Configure RawSocket to capture the peer's wire source address and IPv4
protocol `1`. An unrelated ICMP message can match the frame layout, so select
only the intended peer traffic at capture. With an intervening `IpOverrider`,
set `"opaque-flow-mode": "peer"` explicitly if you want peer-based worker
placement. Set `"fragment-policy": "reassemble"` on the packet adapters.

For a fixed TCP service, a connection bridge can supply the packet side of
each chain. Ordinary UdpListener or UdpConnector normal lines do not supply
the packet lines these nodes require.

## Minimal practical example

Replace `next-node` with the next configured node in the chain. Both settings
are optional and the entire `settings` object may be omitted.

```json
{
  "name": "pingclient",
  "type": "PingClient",
  "settings": {
    "icmp-type": "echo-request",
    "icmp-code": "no-code"
  },
  "next": "next-node"
}
```

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `icmp-type` | `"echo-request"` (8) | Outbound type. Accepts an integer from 0 to 255 or a supported type name. |
| `icmp-code` | `0` | Outbound code. Accepts an integer from 0 to 255 or a supported code name for the selected type. |

Unknown settings, including `local-ipv4` and `peer-ipv4`, are rejected.
Type and code names are lowercase and hyphenated. Type `"echo"` aliases
`"echo-request"`, and `"seamoby"` names type 41. The code name `"no-code"`
applies to types such as Echo Request and Echo Reply. See the
[IANA ICMPv4 registry](https://www.iana.org/assignments/icmp-parameters) for
assigned values.

Each peer can choose an independent type and code. For example,
`"experiment-1"` and `"experiment-2"` resolve to types 253 and 254 for
explicitly configured experiments. `"port-unreachable"` resolves to code 3
with `"destination-unreachable"` (type 3). Numeric settings can express
unassigned values. All numeric pairs use the same frame layout. Network
devices may handle ICMP types and codes differently.

## Usage and troubleshooting

### MTU and reassembly

The encoder adds 10 bytes. A 1,500-byte carrier can therefore hold at most a
1,490-byte native IPv4 packet, including IP options and transport headers. Use
a smaller native MTU if the path has a lower MTU or the chain adds other
headers. Set applicable bridge `mtu`, TunDevice `device-mtu`, and core
`misc.mtu` for both directions. Reassemble fragmented native packets and
carriers at the packet adapters. DF alone is valid.

The decoder validates IPv4 protocol `1`, exact packet length, IPv4 and ICMP
checksums, the opposite sender role, and the native payload's shape. The role
check rejects reflections of the node's own frames. The tunnel carries
plaintext IPv4 data.

## Advanced behavior

```text
[existing IPv4 header and options][ICMP header, 8 bytes][native payload][saved protocol, 1 byte][sender role, 1 byte]
```

The ICMP header starts with the configured type and code and the ICMP
checksum. Its last four bytes are zero on transmit. The checksum covers the
entire ICMP message, including the saved IPv4 protocol in the penultimate byte
and sender role in the final byte (client `1`, server `2`). The decoder restores
the native protocol and length. The decoded header reflects the received
addresses, TTL, DSCP/ECN, ID, DF, and options.

The encoder removes the address contribution from TCP and UDP checksums.
The decoder adds the contribution of the received addresses. A zero IPv4 UDP
checksum stays zero during ordinary framing and address rewriting. If the native
packet explicitly requests checksum repair, Ping performs it before encoding.
For UDP, this computes and enables the checksum even if it was zero.
A repair request on the ICMP carrier affects only its IPv4 and ICMP checksums.
An invalid native transport checksum remains invalid without native repair.

`PingClient` encodes upstream and decodes downstream. Each accepted
packet continues in the same callback direction. Per-node state holds
configuration and drop diagnostics. Packet lines belong to the chain, and the
node has no per-line state.

## Implementation details

| Property | Value |
| --- | --- |
| Node and neighboring layers | `kNodeLayer3` |
| Previous and next edges | Both supported |
| `required_padding_left` | `10` bytes |
| Line state | None |

Lifecycle callbacks pass through in the same direction.
