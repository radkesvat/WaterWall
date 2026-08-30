<!--
Documentation version: 159
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/UdpConnector.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/UdpConnector.mdx, and all files must keep the same documentation version.
-->

# UdpConnector Node

`UdpConnector` is an outbound UDP client node. It manages worker-local UDP sockets, chooses a destination address and port, and forwards datagrams between the previous node and the selected remote peer.

In practice, this node is used at the end of a chain.

`UdpConnector` accepts normal layer-4 lines only. A layer-3 worker packet line
must cross an explicit bridge such as `PacketsToStream` before reaching this
node. Use `StreamToPackets` on the receiving side when the remote payload must
return to a layer-3 packet chain. For direct packet-line UDP endpoint behavior,
use a packet-capable adapter such as `UdpStatelessSocket` instead.

## What It Does

- Manages outbound UDP sockets in worker-local state.
- Chooses a destination address and destination port.
- Resolves a domain name if needed through an internal `DomainResolver`.
- Forwards upstream payload from the previous node to the remote UDP peer.
- Forwards datagrams received from the remote UDP peer back downstream.
- Routes received datagrams back to the originating line and drops datagrams from unregistered peers.
- Tracks the UDP line with idle timeouts.
- Applies optional socket options such as `SO_MARK`, device binding, and source-IP binding when supported by the platform.

This node acts like a chain end. It is started by upstream `init` and does not
need a `next` node.

## Configuration Example

```json
{
  "name": "udp-out",
  "type": "UdpConnector",
    "settings": {
    "address": "example.com",
    "port": "random(40000,40100)",
    "large-send-buffer": true,
    "large-recv-buffer": true,
    "fwmark": 10,
    "interface": "eth0",
    "source-ip": "192.0.2.10",
    "domain-strategy": "prefer-ipv4"
  }
}
```

### Weighted Multi-Destination Example

```json
{
  "name": "udp-out",
  "type": "UdpConnector",
  "settings": {
    "balance-mode": "packet",
    "addresses": [
      {
        "address": "1.1.1.1",
        "port": 53,
        "weight": 3
      },
      {
        "address": "8.8.8.8",
        "port": "random(40000,40100)",
        "weight": 1
      }
    ],
    "large-send-buffer": true,
    "large-recv-buffer": true
  }
}
```

`balance-mode` is not a required JSON field. It stays in `settings`, outside the `addresses` array.

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"UdpConnector"`.

### `settings`

- Either `address` + `port`, or `addresses`

  Choose exactly one style:
  - legacy single-destination fields: `address` and `port`
  - weighted multi-destination field: `addresses` (the parser also accepts `adresses`)

  Do not mix `addresses` with the top-level `address` / `port` fields.

- `address` `(string)`
  Destination address selection for the legacy single-destination form.

  Supported values in the current implementation:
  - a constant IPv4 address
  - a constant IPv6 address
  - a constant domain name
  - `"src_context->address"`
  - `"dest_context->address"`

- `port` `(number or string)`
  Destination port selection for the legacy single-destination form.

  Supported values in the current implementation:
  - a constant number such as `53`
  - a numeric string such as `"53"`
  - `"src_context->port"`
  - `"dest_context->port"`
  - `"random(x,y)"`

  The `random(x,y)` form chooses one random port in the inclusive range `[x, y]` during line initialization.

- `addresses` `(array of objects)`
  Weighted destination list.

  The parser also accepts the alias `adresses`, but `addresses` is the documented spelling.

  Each object must contain:
  - `address`
  - `port`
  - `weight`

  `address` and `port` inside each element support the same forms as the legacy top-level fields.

  `weight` must be a positive integer.
  By default, each new line chooses exactly one element from the array, with probability proportional to its weight.

## Optional `settings` Fields

- `balance-mode` `(string)`
  Controls when weighted destination selection happens.
  This field is optional and defaults to `"connection"`.
  It must be placed directly inside `settings`, not inside each `addresses` element.

  Possible values:
  - `"connection"`: choose one target during upstream `init`; all packets on that WaterWall line keep using that target.
  - `"packet"`: choose a target for each upstream payload packet before sending it.

- `large-send-buffer` `(boolean or positive integer)`
  Sets `SO_SNDBUF` on created UDP sockets.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged. A positive integer sets the requested byte size directly.
  Default: `true`

- `large-recv-buffer` `(boolean or positive integer)`
  Sets `SO_RCVBUF` on created UDP sockets.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged. A positive integer sets the requested byte size directly.
  Default: `true`

- `fwmark` `(integer)`
  Linux-style socket mark.
  When the platform provides `SO_MARK`, this value is applied to the UDP socket before bind.
  Default: not set

- `interface` `(string)`
  Restricts the UDP socket to a local network device where supported.
  On Linux this uses `SO_BINDTODEVICE`. On platforms without device binding, WaterWall falls back to binding the socket to the interface's IPv4 address.

- `source-ip` `(string)`
  Binds the UDP socket to a specific local source IP with an ephemeral source port.
  This is useful when the host has multiple local addresses and the default route would choose the wrong source address.
  If `TunDevice` loop protection has published an automatic egress pin, `source-ip` alone does not override that pin. Make sure the source IP belongs to the pinned/default interface, or set `interface` explicitly.

- `domain-strategy` `(string or integer)`
  Selects how domain DNS results are chosen.
  Default: the core `dns.domain-strategy` value. If the core value is omitted, the default is `"prefer-ipv4"`.

  Supported string values:
  - `"accept-dns-returned-order"`: use addresses in the resolver's returned order
  - `"prefer-ipv4"`: use IPv4 first, fallback to IPv6
  - `"prefer-ipv6"`: use IPv6 first, fallback to IPv4
  - `"only-ipv4"`: use only IPv4 addresses
  - `"only-ipv6"`: use only IPv6 addresses

  Legacy integer values are still accepted:
  - `0`: accept DNS returned order
  - `1`: prefer IPv4
  - `2`: prefer IPv6
  - `3`: only IPv4
  - `4`: only IPv6

## Detailed Behavior

### Socket setup

During upstream `init`, `UdpConnector`:

- computes the destination address and port for this line
- maps `domain-strategy` onto the line destination context
- resolves the domain if needed through its internal `DomainResolver`
- prepares worker-local UDP resources for the resolved destination
- applies the configured buffers, source IP, interface, `fwmark`, and egress pin
  to any socket it creates
- starts receive processing as needed and stores independent line state and idle
  tracking

Unlike TCP, this tunnel does not perform a connection handshake.

### Address and port selection

The destination address can come from:

- a constant JSON value
- `src_context->address`
- `dest_context->address`

The destination port can come from:

- a constant number
- a numeric string
- `src_context->port`
- `dest_context->port`
- `random(x,y)`

This makes `UdpConnector` useful after nodes that fill routing context dynamically.

An internal protocol tunnel can also mark a negotiated destination as authoritative for one outbound adapter. In that
case `UdpConnector` preserves the supplied address and port instead of applying its configured destination selector or
packet balancing. This is internal chain metadata, not a user JSON setting; it lets a SOCKS5 UDP relay use the
`BND.ADDR`/`BND.PORT` that its proxy negotiated.

Observed-protocol metadata may be cleared by a preceding `Router` or sniffer,
but this route-control authority survives that narrow reset. `UdpConnector`
consumes the authority exactly once during outbound setup and clears it before
normal later routing decisions.

When `addresses` is used, the same selection rules apply inside each array element.
In the default `"connection"` balance mode, the connector first picks one destination object by weight, then resolves that chosen object's `address` and `port` for the line.
In `"packet"` balance mode, the weighted choice happens for every upstream payload packet. A normal line may use both IPv4 and IPv6 destinations. Socket selection and local source-port selection are managed internally.

### Domain resolution

If the selected address is a domain name, the internal `DomainResolver` submits asynchronous DNS on the line's worker during upstream `init`. Payloads that arrive before resolution completes are kept in the resolver's bounded pending queue. If resolution fails, the line is finished immediately.

In `"packet"` balance mode, domain names inside packet-balanced destination objects are resolved lazily per destination object on each WaterWall line. The first packet that selects an unresolved domain starts one async DNS request for that destination and packets for that destination wait in a bounded queue. Destination resources are prepared before that queue is flushed; failure drops only the affected destination queue. Static destination contexts are cached, while destinations sourced from mutable line context are rebuilt before use. If mutable context changes while an earlier DNS request for the same destination slot is still pending, the new packet is dropped instead of being queued for the obsolete request. There is no time-based DNS cache and no per-packet DNS request.

### Establishment semantics

There is no true UDP connect handshake here.

Establishment works as follows:

- upstream `init` prepares the local UDP resources
- downstream `est` is emitted after those resources are ready to send
- upstream payload can be sent immediately after that

So from the previous node's point of view, this tunnel becomes established when
the local UDP path is ready, not after a remote reply.

### Worker-local socket management

Socket state is worker-local and address-family-aware. Replies are accepted only
from expected peer endpoints; unknown sources are dropped. Local socket and
source-port behavior is connector-managed and must not be used as line identity.
Pause and idle state remain per line.

### Data flow direction

- Previous node to remote peer: upstream payload -> UDP send
- Remote peer to previous node: UDP receive -> downstream payload

In both balance modes, received datagrams are accepted only from registered
peers and routed to the originating line.

### Pause behavior

When paused, `UdpConnector` does not queue received datagrams.

If a datagram arrives while reads are paused:

- that datagram is dropped
- reads continue again after resume

### Idle timeout behavior

Idle UDP lines expire automatically, and continuing traffic extends the idle
deadline. On expiry, connector state is released and downstream `finish` is sent
to the previous node.

### Random destination port selection

If `port` uses `random(x,y)` with `"connection"` balance mode, the destination port is chosen once during line initialization. After that, the line keeps using that selected port for its lifetime.
With `"packet"` balance mode, a `random(x,y)` port is selected when that destination object is first materialized on the line, then reused for later packets that choose the same destination object.

## Notes And Caveats

- Domain resolution in this path is asynchronous and keeps pre-resolution datagrams queued up to the connector queue limit.
- `fwmark` and device binding are platform-dependent. `fwmark` is not available on Windows.
- Connection-init DNS resolution is handled by an internal `DomainResolver`; `UdpConnector` keeps its own public `domain-strategy` vocabulary.
- Paused reads drop inbound datagrams instead of buffering them.
- Local source ports are connector-managed and must not be used as line
  identifiers.
- `PacketsToStream` currently bridges self-consistent IPv4 packets and does not
  copy mutable per-packet routing context onto its normal output line. Use
  `PacketsToConnection` for per-flow IPv4 TCP/UDP conversion, or a packet-capable
  UDP adapter when direct packet-line routing semantics are required.
- Downstream `est` is triggered after the local UDP path is ready.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainEnd` |
| `can_have_prev` | `true` |
| `can_have_next` | `false` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayerNone` |
| `required_padding_left` | `0` bytes |
