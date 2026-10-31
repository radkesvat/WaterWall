# FakeTcpHeaderClient Node

`FakeTcpHeaderClient` is the client end of a stateless fake-TCP packet carrier.
It wraps each complete inner IPv4 packet in an outer IPv4 header and a
TCP-shaped header, and unwraps the carriers that its peer
[FakeTcpHeaderServer](../FakeTcpHeaderServer/description.md) sends back.

There is no TCP connection: no handshake, no sequence tracking, no
retransmission. Every carrier is an independent packet whose TCP fields come
from a fixed template. The node is a pure packet tunnel
(`packettunnelCreate()`), has no line state and only transforms packets. It
does not choose public addresses or another outer protocol; `IpOverrider` and
`IpManipulator` do that (see [Composition](#composition)).

| Event | Action |
| --- | --- |
| upstream inner IPv4 packet | Encode a carrier from `client-port + i` to `server-port` and forward it upstream. |
| downstream carrier | Verify and strip the carrier headers and forward the inner packet downstream. |
| refused packet | Drop it on its worker and emit a rate-limited diagnostic. |

## Chain Order

```text
client (UDP listener): UdpListener -> ConnectionToPackets -> FakeTcpHeaderClient -> IpOverrider -> RawSocket
client (TUN):          TunDevice   -> FakeTcpHeaderClient -> IpOverrider -> RawSocket

server:                RawSocket -> IpOverrider -> FakeTcpHeaderServer -> PacketsToConnection -> UdpConnector
                       RawSocket -> IpOverrider -> FakeTcpHeaderServer -> TunDevice
```

Requests travel upstream in both chains and replies travel downstream. Both
neighbours must be Layer-3 packet nodes: use `TunDevice`, or
`ConnectionToPackets` to turn ordinary connection lines into inner packets. Do not
connect the node directly to a UDP listener or connector.

## Configuration Example

```json
{
  "name": "fake-tcp-header",
  "type": "FakeTcpHeaderClient",
  "settings": {
    "server-port": 40000,
    "client-port": 40001,
    "client-port-count": 16,
    "sequence": 12345,
    "acknowledgment": 67890,
    "window": 65535,
    "urgent-pointer": 0,
    "options": "01010101"
  },
  "next": "carrier-addresses"
}
```

Both nodes of a pair accept the same keys. The `settings` object is optional;
every key has a default.

| Setting | Default | Meaning |
| --- | --- | --- |
| `server-port` | `40000` | Carrier TCP port of the server side. Integer `1..65535`. |
| `client-port` | `40001` | First carrier TCP port of the client side. Integer `1..65535`. |
| `client-port-count` | `16` | Number of client carrier ports. Integer `1..1024`; `client-port + client-port-count - 1` must not exceed `65535`, and `server-port` must lie outside `[client-port, client-port + client-port-count)`. |
| `sequence` | `0` | TCP sequence number of every outgoing carrier. Integer `0..4294967295`. |
| `acknowledgment` | `0` | TCP acknowledgment number of every outgoing carrier. Integer `0..4294967295`. |
| `window` | `65535` | TCP window of every outgoing carrier. Integer `0..65535`. |
| `urgent-pointer` | `0` | TCP urgent pointer of every outgoing carrier. Integer `0..65535`. |
| `options` | `""` | TCP option bytes as a hexadecimal string: `0..40` bytes, a multiple of 4 bytes. They are emitted verbatim, so include any NOP/EOL padding yourself; the data offset follows from their length. |

Unknown keys, explicit `null`, wrong types, fractions and out-of-range values
fail node creation with `JSON Error: FakeTcpHeaderClient->settings-><key> :
<expectation>`. There are no settings for addresses, the outer protocol, TCP
flags or an MTU.

Both peers must use the same `server-port`, `client-port` and
`client-port-count`. The other fields may differ between the peers: receive
reads the data offset from each carrier and does not compare sequence,
acknowledgment, window, urgent pointer, flags or options with its own template.

## Wire Rules

Every carrier, in both directions, is exactly:

```text
outer IPv4 header (20 bytes) | TCP header (20 bytes + options) | complete inner IPv4 packet (unchanged bytes)
```

- Outer IPv4: version 4 with a 20-byte header, TOS = inner TOS with the ECN
  bits cleared (DSCP copied, ECN Not-ECT), total length, ID `0`, DF set,
  TTL `64`, protocol `6` and a valid header checksum. Source and destination
  are copied from the inner packet.
- TCP: ports per the [port mapping](#per-flow-carrier-ports); sequence,
  acknowledgment, window and urgent pointer from the settings; data offset
  from the options length; flags ACK|PSH (`0x18`); options verbatim; a valid
  checksum over the standard pseudo-header (protocol 6, outer addresses).
- The carrier is at most 1500 bytes, so the inner packet is at most
  `1500 - (40 + options length)` bytes.

Receive accepts a carrier only when it is one complete, unfragmented IPv4 TCP
packet of at most 1500 bytes whose total length equals the packet length, whose
TCP data offset lies inside the segment and whose ports match the mapping.
Outer IPv4 options are allowed and stripped with the header. The outer IPv4
and TCP checksums must verify, unless an internal checksum-repair request is
pending on the packet. The remainder must be exactly one complete IPv4 packet.
Outer addresses are never checked: RawSocket's capture filter selects the
carriers and IpOverrider owns the addresses.

## Per-Flow Carrier Ports

Each inner packet selects one client carrier port:

```text
i = deviceFlowWorkerHash(inner packet) % client-port-count     (0 when the packet cannot be hashed)

client -> server: source client-port + i, destination server-port
server -> client: source server-port,     destination client-port + i
```

The hash covers the inner addresses, protocol and, for TCP, UDP and SCTP, the
inner ports. It is endpoint-symmetric, so a request and its reply select the
same `i`. Packets without ports (ICMP and others) share one `i` per address
pair and protocol. All fragments of one inner datagram share one `i` (the IPv4
identification replaces the ports), which may differ from the `i` of the
flow's unfragmented packets.

RawSocket steers captured TCP by addresses and the first four bytes after the
IPv4 header, which are the carrier ports. With `multi-queue` the kernel
spreads carriers over the receive queues by that hash; with one queue,
software applies the same hash before handing packets to workers. Different
inner flows therefore spread over capture queues and workers, while all
carriers of one inner flow carry the same ports and stay on one queue and one
worker, in order. With `client-port-count: 1` every carrier of the peer pair
uses one queue and one worker.

Capture filters key on `server-port` alone, because every carrier has it on
one side:

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

That is the client side: `capture-ips` is the server's public IPv4 and
`capture-tcp-source-port` is `server-port`. The server uses the client's public
IPv4 with `capture-tcp-dest-port: 40000`; see
[FakeTcpHeaderServer](../FakeTcpHeaderServer/description.md#receive-filtering).
No range filter for the client ports is needed: decode rejects any carrier
whose client port lies outside the configured range.

Reserve `server-port` between the two carrier addresses. Genuine TCP between
the client and the server that uses `server-port` on the server's end is
captured and dropped on both hosts, so do not run a service on it for this
client, and keep it out of the server's ephemeral port range (for example with
`net.ipv4.ip_local_reserved_ports`). The client port range needs no
reservation. Tuple filtering provides no authentication.

## Composition

**Carrier addresses.** The outer addresses are the inner packet's addresses,
which are often private. One `IpOverrider` between the carrier node and
RawSocket sets the public carrier addresses. On the client:

```json
{
  "name": "carrier-addresses",
  "type": "IpOverrider",
  "settings": {
    "up": {
      "source-ip": { "ipv4": "192.0.2.10" },
      "dest-ip": { "ipv4": "198.51.100.10" }
    }
  },
  "next": "raw"
}
```

`up.source-ip` is the client public IPv4 and `up.dest-ip` the server public
IPv4. Incoming carriers need no `down` rule because decode ignores the outer
addresses. The server mirrors this with `down` rules (see
[FakeTcpHeaderServer](../FakeTcpHeaderServer/description.md#composition)).
`IpOverrider` updates the IPv4 and TCP checksums incrementally, so carriers
stay valid.

**Other TCP flags.** Every carrier is sent with ACK|PSH. To emit other flags,
place an `IpManipulator` between the carrier node and RawSocket: with
`up-tcp-bit-*` settings on the client, where outgoing carriers travel
upstream, and with `dw-tcp-bit-*` settings on the server, where they travel
downstream. Decode does not check the flags, so the receiving side needs no
matching rule.

**Another outer protocol.** To send carriers with an IP protocol other than 6,
place an `IpManipulator` with `protoswap-tcp` next to the carrier node on both
peers, for example
`FakeTcpHeaderClient -> IpManipulator -> IpOverrider -> RawSocket`. The swap
toggles between 6 and the configured number in both directions, so decode
still sees protocol 6. RawSocket then captures that protocol without port
qualifiers, for example `"capture-protocols": [253]`; with its default
`opaque-flow-mode: "prefix"` it still steers by the first four bytes after the
IPv4 header, the carrier ports.

## MTU and Validation

The limits count complete IPv4 packets:

```text
overhead       = 20-byte IPv4 + 20-byte TCP + options length
inner MTU      = 1500 - overhead
UDP payload    = inner MTU - inner IPv4 header - 8-byte UDP header
```

| `options` length | Inner MTU | UDP payload (20-byte inner IPv4 header) |
| --- | --- | --- |
| 0 bytes | 1460 | 1432 bytes |
| 4 bytes | 1456 | 1428 bytes |
| 40 bytes | 1420 | 1392 bytes |

Set `TunDevice.device-mtu` or `ConnectionToPackets.mtu` (both default to core
`misc.mtu`) to the inner MTU, and on the server `PacketsToConnection.mtu` or
`TunDevice.device-mtu`. A lower path MTU requires smaller values. The node
does not fragment, segment, discover PMTU or adjust TCP MSS.

- **Inner fragments.** `TunDevice` reassembles by default (`fragment-policy:
  "reassemble"`), so a datagram larger than the inner MTU reaches the node
  whole and is dropped as oversized. Use `preserve-fragments` on a sending
  `TunDevice` only when the receiving side is also a `TunDevice`: the
  fragments are then carried one per carrier and the receiving kernel
  reassembles them. `ConnectionToPackets` emits UDP datagrams above its `mtu`
  as fragments, which are also carried one per carrier. `PacketsToConnection`
  and `ConnectionToPackets` drop the inner fragments they receive, so keep
  datagrams within the inner MTU when either is the receiver.
- **IPv4 only.** Each input must be exactly one complete IPv4 packet whose
  total length equals the buffer length. IPv6, malformed input and trailing
  bytes are dropped.
- **Inner checksums.** Inner packets are checked for framing only. Their
  checksums are never verified, so intentionally invalid checksums, such as
  those `IpManipulator`'s SNI tricks produce, are carried unchanged.
- **Checksum repair.** A pending internal checksum-repair request is honoured
  by repairing the inner packet before it is wrapped; a refused repair drops
  the packet. On receive a pending request skips outer checksum verification.
  A successful encode or decode clears the request.
- **ECN.** The outer ECN field is always Not-ECT, because a congestion mark on
  the carrier could not be passed on to the inner packet. The inner TOS byte,
  including its ECN bits, is carried unchanged.
- **Headroom.** Encoding prepends the headers in place and needs `40 + options
  length` bytes of left capacity; the node advertises 80 bytes of padding, the
  maximum.

Refused packets leave their bytes unchanged and are dropped on their worker.
Drop logs use the network logger at `ERROR` level, and each drop log names its
reason:

- outgoing inner packets: not one complete IPv4 packet, larger than the
  inner MTU, insufficient left headroom, or a refused checksum repair; the log
  gives `packet-bytes`, `max-inner-bytes`, `overhead-bytes` and
  `headroom-bytes`;
- incoming carriers: not one complete unfragmented IPv4/TCP packet of at most
  1500 bytes, carrier ports outside the mapping, an invalid outer IPv4 or TCP
  checksum, or a payload that is not one complete IPv4 packet; the log gives
  `packet-bytes` and `max-carrier-bytes`.

At most one drop log per node is emitted every 5 seconds; the limit is shared
by all reasons, both directions and all workers.

## Limits and Detectability

- Sequence, acknowledgment, window, urgent pointer, options and flags are the
  same on every carrier and never advance, and the inner IPv4 header follows
  the TCP header directly. That pattern is easy to fingerprint.
- There is no handshake. Stateful firewalls, NAT devices and middleboxes that
  track TCP state may drop carriers.
- A NAT that rewrites the carrier ports breaks decode: the server port and
  client range must arrive unchanged.
- There is no authentication or encryption. The inner packet is carried in
  clear text, and anyone who can send packets with a captured source address
  and the right ports can inject inner packets or probe for the peer. Run
  encrypted or obfuscated traffic inside the carrier. UDP keeps its loss and
  reordering behaviour.

## Examples

- [examples/client](examples/client/config.json):
  `UdpListener -> ConnectionToPackets -> FakeTcpHeaderClient -> IpOverrider -> RawSocket`.
  It accepts UDP on `127.0.0.1:5000`; inner packets go from `10.90.0.1` to
  `10.90.0.2:5300`.
- [examples/client-tun](examples/client-tun/config.json):
  `TunDevice -> FakeTcpHeaderClient -> IpOverrider -> RawSocket`. It assigns
  `10.90.0.1/24` to TUN; send UDP to `10.90.0.2:5300` and keep `10.90.0.2`
  unassigned so the kernel routes it into TUN.
- [FakeTcpHeaderServer examples/server](../FakeTcpHeaderServer/examples/server/config.json):
  the server for both, forwarding to UDP `127.0.0.1:5300`.

The examples use the documentation addresses `192.0.2.10` (client) and
`198.51.100.10` (server); replace them with the hosts' public IPv4 addresses
in the IpOverrider and RawSocket settings. Run Waterwall from the example
directory with its `core.json`, which sets `misc.mtu` to the inner MTU 1460.
In the TUN example `route-table: "off"` leaves route selection to you: keep
the server's public address reachable through the ordinary interface so
carriers cannot loop back into TUN.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| `version` | `1` |
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer3` |
| `layer_group_prev_node` | `kNodeLayer3` |
| `layer_group_next_node` | `kNodeLayer3` |
| `required_padding_left` | `80` bytes |
| line state | none |

Build option: `INCLUDE_FAKE_TCP_HEADER_CLIENT` (default `TRUE`).
