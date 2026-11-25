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
| `icmp-type` | `"echo-request"` (`8`) | Outbound ICMPv4 type. Use a [type name](#icmp-type-names) or a JSON integer from `0` to `255`. |
| `icmp-code` | `0` | Outbound ICMPv4 code. Use a [code name](#icmp-code-names) for the selected type or a JSON integer from `0` to `255`. |

Unknown settings, including `local-ipv4` and `peer-ipv4`, are rejected.
Use the lowercase, hyphenated strings shown in the tables. Code names
depend on the selected type, whether you set `icmp-type` as a string or
a number. For example, `"port-unreachable"` maps to code `3` with
`"destination-unreachable"` or numeric type `3`. Omitting `icmp-code`
uses code `0` for any type.

Each peer can choose an independent type and code. All pairs use the same
frame layout. Network devices may handle ICMP types and codes differently.
See the [IANA ICMPv4 registry](https://www.iana.org/assignments/icmp-parameters)
for assigned values.

### ICMP type names

| `icmp-type` string | Type number |
| --- | --- |
| `"echo-reply"` | `0` |
| `"destination-unreachable"` | `3` |
| `"source-quench"` | `4` |
| `"redirect"` | `5` |
| `"alternate-host-address"` | `6` |
| `"echo-request"` | `8` |
| `"echo"` | `8` |
| `"router-advertisement"` | `9` |
| `"router-solicitation"` | `10` |
| `"time-exceeded"` | `11` |
| `"parameter-problem"` | `12` |
| `"timestamp"` | `13` |
| `"timestamp-reply"` | `14` |
| `"information-request"` | `15` |
| `"information-reply"` | `16` |
| `"address-mask-request"` | `17` |
| `"address-mask-reply"` | `18` |
| `"traceroute"` | `30` |
| `"datagram-conversion-error"` | `31` |
| `"mobile-host-redirect"` | `32` |
| `"ipv6-where-are-you"` | `33` |
| `"ipv6-i-am-here"` | `34` |
| `"mobile-registration-request"` | `35` |
| `"mobile-registration-reply"` | `36` |
| `"domain-name-request"` | `37` |
| `"domain-name-reply"` | `38` |
| `"skip"` | `39` |
| `"photuris"` | `40` |
| `"seamoby"` | `41` |
| `"extended-echo-request"` | `42` |
| `"extended-echo-reply"` | `43` |
| `"experiment-1"` | `253` |
| `"experiment-2"` | `254` |

### ICMP code names

Use a numeric code for any value without a name under the selected type.

| `icmp-type` | `icmp-code` string | Code number |
| --- | --- | --- |
| `"echo-reply"` (`0`) | `"no-code"` | `0` |
| `"destination-unreachable"` (`3`) | `"net-unreachable"` | `0` |
| `"destination-unreachable"` (`3`) | `"host-unreachable"` | `1` |
| `"destination-unreachable"` (`3`) | `"protocol-unreachable"` | `2` |
| `"destination-unreachable"` (`3`) | `"port-unreachable"` | `3` |
| `"destination-unreachable"` (`3`) | `"fragmentation-needed-and-dont-fragment-was-set"` | `4` |
| `"destination-unreachable"` (`3`) | `"source-route-failed"` | `5` |
| `"destination-unreachable"` (`3`) | `"destination-network-unknown"` | `6` |
| `"destination-unreachable"` (`3`) | `"destination-host-unknown"` | `7` |
| `"destination-unreachable"` (`3`) | `"source-host-isolated"` | `8` |
| `"destination-unreachable"` (`3`) | `"communication-with-destination-network-is-administratively-prohibited"` | `9` |
| `"destination-unreachable"` (`3`) | `"communication-with-destination-host-is-administratively-prohibited"` | `10` |
| `"destination-unreachable"` (`3`) | `"destination-network-unreachable-for-type-of-service"` | `11` |
| `"destination-unreachable"` (`3`) | `"destination-host-unreachable-for-type-of-service"` | `12` |
| `"destination-unreachable"` (`3`) | `"communication-administratively-prohibited"` | `13` |
| `"destination-unreachable"` (`3`) | `"host-precedence-violation"` | `14` |
| `"destination-unreachable"` (`3`) | `"precedence-cutoff-in-effect"` | `15` |
| `"source-quench"` (`4`) | `"no-code"` | `0` |
| `"redirect"` (`5`) | `"redirect-datagram-for-the-network-or-subnet"` | `0` |
| `"redirect"` (`5`) | `"redirect-datagram-for-the-host"` | `1` |
| `"redirect"` (`5`) | `"redirect-datagram-for-the-type-of-service-and-network"` | `2` |
| `"redirect"` (`5`) | `"redirect-datagram-for-the-type-of-service-and-host"` | `3` |
| `"alternate-host-address"` (`6`) | `"alternate-address-for-host"` | `0` |
| `"echo-request"` (`8`) | `"no-code"` | `0` |
| `"router-advertisement"` (`9`) | `"normal-router-advertisement"` | `0` |
| `"router-advertisement"` (`9`) | `"does-not-route-common-traffic"` | `16` |
| `"router-solicitation"` (`10`) | `"no-code"` | `0` |
| `"time-exceeded"` (`11`) | `"time-to-live-exceeded-in-transit"` | `0` |
| `"time-exceeded"` (`11`) | `"fragment-reassembly-time-exceeded"` | `1` |
| `"parameter-problem"` (`12`) | `"pointer-indicates-the-error"` | `0` |
| `"parameter-problem"` (`12`) | `"missing-a-required-option"` | `1` |
| `"parameter-problem"` (`12`) | `"bad-length"` | `2` |
| `"timestamp"` (`13`) | `"no-code"` | `0` |
| `"timestamp-reply"` (`14`) | `"no-code"` | `0` |
| `"information-request"` (`15`) | `"no-code"` | `0` |
| `"information-reply"` (`16`) | `"no-code"` | `0` |
| `"address-mask-request"` (`17`) | `"no-code"` | `0` |
| `"address-mask-reply"` (`18`) | `"no-code"` | `0` |
| `"photuris"` (`40`) | `"bad-spi"` | `0` |
| `"photuris"` (`40`) | `"authentication-failed"` | `1` |
| `"photuris"` (`40`) | `"decompression-failed"` | `2` |
| `"photuris"` (`40`) | `"decryption-failed"` | `3` |
| `"photuris"` (`40`) | `"need-authentication"` | `4` |
| `"photuris"` (`40`) | `"need-authorization"` | `5` |
| `"extended-echo-request"` (`42`) | `"no-error"` | `0` |
| `"extended-echo-reply"` (`43`) | `"no-error"` | `0` |
| `"extended-echo-reply"` (`43`) | `"malformed-query"` | `1` |
| `"extended-echo-reply"` (`43`) | `"no-such-interface"` | `2` |
| `"extended-echo-reply"` (`43`) | `"no-such-table-entry"` | `3` |
| `"extended-echo-reply"` (`43`) | `"multiple-interfaces-satisfy-query"` | `4` |

## Usage and troubleshooting

### MTU and reassembly

The encoder adds 10 bytes. A 1,500-byte carrier can therefore hold at most a
1,490-byte native IPv4 packet, including IP options and transport headers. Use
a smaller native MTU if the path has a lower MTU or the chain adds other
headers. Set applicable bridge `mtu`, TunDevice `device-mtu`, and core
`misc.mtu` for both directions. Reassemble fragmented native packets and
carriers at the packet adapters. DF alone is valid.

Both the encoder and decoder drop packets whose IPv4 header contains Loose
Source and Record Route (LSRR) or Strict Source and Record Route (SSRR).
Other well-formed IPv4 options pass through.

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
