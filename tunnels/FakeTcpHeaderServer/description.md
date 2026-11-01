# FakeTcpHeaderServer Node

`FakeTcpHeaderServer` is the server end of the stateless fake-TCP packet
carrier. It unwraps the carriers that
[FakeTcpHeaderClient](../FakeTcpHeaderClient/description.md) sends, restoring
each complete inner IPv4 packet, and wraps reply packets in carriers toward
the client.

There is no TCP connection: no handshake, no listening socket, no sequence
tracking. Every carrier is an independent packet whose TCP fields come from a
fixed template. The node is a pure packet tunnel (`packettunnelCreate()`), has
no line state and only transforms packets. Carrier addresses come from
`IpOverrider`; another outer protocol or other TCP flags come from
`IpManipulator`.

| Event | Action |
| --- | --- |
| upstream carrier | Verify and strip the carrier headers and forward the inner packet upstream. |
| downstream inner IPv4 packet | Encode a carrier from `server-port` to `client-port + i` and forward it downstream. |
| refused packet | Drop it on its worker and emit a rate-limited diagnostic. |

## Chain Order

```text
server: RawSocket -> IpOverrider -> FakeTcpHeaderServer -> PacketsToConnection -> UdpConnector
        RawSocket -> IpOverrider -> FakeTcpHeaderServer -> TunDevice

client: UdpListener -> ConnectionToPackets -> FakeTcpHeaderClient -> IpOverrider -> RawSocket
        TunDevice   -> FakeTcpHeaderClient -> IpOverrider -> RawSocket
```

RawSocket is the first node of the server chain. Requests travel upstream and
replies downstream. Use `PacketsToConnection` to expose received inner TCP/UDP
flows to ordinary connectors, or `TunDevice` to deliver them to the kernel.
Both neighbours must be Layer-3 packet nodes; do not connect the node directly
to a UDP listener or connector.

## Configuration Example

```json
{
  "name": "fake-tcp-header",
  "type": "FakeTcpHeaderServer",
  "settings": {
    "server-port": 40000,
    "client-port": 40001,
    "client-port-count": 16,
    "sequence": 67890,
    "acknowledgment": 12345,
    "window": 65535
  },
  "next": "flows"
}
```

The settings are the same as on
[FakeTcpHeaderClient](../FakeTcpHeaderClient/description.md#configuration-example).
The `settings` object is optional; every key has a default.

| Setting | Default | Meaning |
| --- | --- | --- |
| `server-port` | `40000` | Carrier TCP port of the server side. Integer `1..65535`. |
| `client-port` | `40001` | First carrier TCP port of the client side. Integer `1..65535`. |
| `client-port-count` | `16` | Number of client carrier ports. Integer `1..1024`; `client-port + client-port-count - 1` must not exceed `65535`, and `server-port` must lie outside `[client-port, client-port + client-port-count)`. |
| `sequence` | `0` | TCP sequence number of every outgoing carrier. Integer `0..4294967295`. |
| `acknowledgment` | `0` | TCP acknowledgment number of every outgoing carrier. Integer `0..4294967295`. |
| `window` | `65535` | TCP window of every outgoing carrier. Integer `0..65535`. |
| `urgent-pointer` | `0` | TCP urgent pointer of every outgoing carrier. Integer `0..65535`. |
| `options` | `""` | TCP option bytes as a hexadecimal string: `0..40` bytes, a multiple of 4 bytes, emitted verbatim. |

Unknown keys, explicit `null`, wrong types, fractions and out-of-range values
fail node creation with `JSON Error: FakeTcpHeaderServer->settings-><key> :
<expectation>`, and a non-object `settings` fails it with
`JSON Error: FakeTcpHeaderServer->settings : expected an object`. An `options`
string of odd length, with non-hex characters, not a multiple of 4 bytes or
longer than 40 bytes also fails creation. `server-port`, `client-port` and
`client-port-count` must match the client; the other fields may differ,
because receive does not compare them with the local template.

## Wire Rules

The carrier format, outer header fields and checksums are those described in
[FakeTcpHeaderClient Wire Rules](../FakeTcpHeaderClient/description.md#wire-rules).
For the server:

- an incoming carrier is accepted only when its destination port is
  `server-port` and its source port lies in
  `[client-port, client-port + client-port-count)`;
- a reply carrier is sent from `server-port` to `client-port + i`, where `i`
  is computed from the inner reply packet exactly as the client computes it
  from the request. The hash is endpoint-symmetric, so the reply uses the
  client port of its request
  ([Per-Flow Carrier Ports](../FakeTcpHeaderClient/description.md#per-flow-carrier-ports));
- outer addresses are never checked on receive. The outer addresses of a
  reply carrier are copied from the inner reply; `IpOverrider` sets them.

Because every inner flow keeps one client port, RawSocket spreads the flows
over its capture queues and workers while keeping each flow on one queue and
worker, in order.

## Receive Filtering

Capture carriers from the client's public IPv4 by their destination port:

```json
{
  "name": "raw",
  "type": "RawSocket",
  "settings": {
    "capture-filter-mode": "source-ip",
    "capture-ips": ["192.0.2.10"],
    "capture-protocols": [6],
    "capture-tcp-dest-port": 40000
  },
  "next": "carrier-addresses"
}
```

`capture-tcp-dest-port` is `server-port`. No filter for the client port range
is needed: every carrier has `server-port` as its destination, and decode
rejects source ports outside the range. Reserve `server-port` for the
carriers: do not run a TCP service on it for this client, and keep it out of
the ephemeral port range (for example with
`net.ipv4.ip_local_reserved_ports`), since genuine TCP from the client to that
port is captured and dropped. Tuple filtering provides no authentication.

## Composition

One `IpOverrider` between RawSocket and the carrier node sets the public
carrier addresses of replies:

```json
{
  "name": "carrier-addresses",
  "type": "IpOverrider",
  "settings": {
    "down": {
      "source-ip": { "ipv4": "198.51.100.10" },
      "dest-ip": { "ipv4": "192.0.2.10" }
    }
  },
  "next": "fake-tcp-header"
}
```

`down.source-ip` is the server public IPv4 and `down.dest-ip` the client
public IPv4. Incoming carriers need no `up` rule because decode ignores the
outer addresses.

Reply carriers travel downstream, so other TCP flags come from an
`IpManipulator` with `dw-tcp-bit-*` settings between RawSocket and the node.
For another
outer protocol, place an `IpManipulator` with `protoswap-tcp` next to the
carrier node on both peers and capture that protocol without port qualifiers;
see [FakeTcpHeaderClient Composition](../FakeTcpHeaderClient/description.md#composition).

## MTU and Validation

The inner MTU is `1500 - (40 + options length)`: 1460 without options. The
limits, fragment handling, checksum and ECN rules are described in
[FakeTcpHeaderClient MTU and Validation](../FakeTcpHeaderClient/description.md#mtu-and-validation).
On the server:

- set `PacketsToConnection.mtu` or `TunDevice.device-mtu` (both default to
  core `misc.mtu`) to the inner MTU, so replies are not larger than a carrier
  can hold;
- `PacketsToConnection` drops inner fragments, so with it on the server keep
  client datagrams within the inner MTU; a `TunDevice` delivers fragments to
  its kernel for reassembly;
- inner packets are checked for framing only; intentionally invalid inner
  checksums are carried unchanged.

Each drop log names its reason:

- incoming carriers: not one complete unfragmented IPv4/TCP packet of at most
  1500 bytes, carrier ports outside the mapping, an invalid outer IPv4 or TCP
  checksum, or a payload that is not one complete IPv4 packet; the log gives
  `packet-bytes` and `max-carrier-bytes`;
- outgoing replies: not one complete IPv4 packet, larger than the inner MTU,
  insufficient left headroom, or a refused checksum repair; the log gives
  `packet-bytes`, `max-inner-bytes`, `overhead-bytes` and `headroom-bytes`.

Drop logs use the network logger at `ERROR` level. At most one drop log per
node is emitted every 5 seconds, shared by all reasons, both directions and
all workers.

## Limits and Detectability

The carrier has a constant TCP header, no handshake, no authentication and no
encryption. Stateful firewalls and NAT may drop carriers, NAT port rewriting
breaks decode, and anyone who can send packets from the client's address to
`server-port` can inject inner packets. Run encrypted or obfuscated traffic
inside the carrier. See
[FakeTcpHeaderClient Limits and Detectability](../FakeTcpHeaderClient/description.md#limits-and-detectability).

## Examples

- [examples/server](examples/server/config.json):
  `RawSocket -> IpOverrider -> FakeTcpHeaderServer -> PacketsToConnection -> UdpConnector`,
  forwarding inner UDP to `127.0.0.1:5300`. It serves both
  [FakeTcpHeaderClient examples/client](../FakeTcpHeaderClient/examples/client/config.json)
  and
  [FakeTcpHeaderClient examples/client-tun](../FakeTcpHeaderClient/examples/client-tun/config.json).

The example uses the documentation addresses `198.51.100.10` (server) and
`192.0.2.10` (client); replace them with the hosts' public IPv4 addresses in
the RawSocket and IpOverrider settings. Run Waterwall from the example
directory with its `core.json`, which sets `misc.mtu` to the inner MTU 1460.
`UdpConnector` can override the destination address and port, while
`PacketsToConnection` keeps the original inner tuple for replies.

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

Build option: `INCLUDE_FAKE_TCP_HEADER_SERVER` (default `TRUE`).
