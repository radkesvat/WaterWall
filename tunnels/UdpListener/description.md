<!--
Documentation version: 155
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/UdpListener.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/UdpListener.mdx, and all files must keep the same documentation version.
-->

# UdpListener Node

`UdpListener` is a UDP server node. It listens for inbound UDP traffic, groups packets by remote peer, creates a line for each peer, and passes packets upstream to the next node in the chain.

In practice, this node is used at the beginning of a chain.

## What It Does

- Binds and listens on one UDP port, several explicit UDP ports, or a UDP port range.
- Accepts inbound UDP packets through the socket manager.
- Applies optional filtering such as whitelist/blacklist checks and balance groups.
- Creates one line per remote peer address and port.
- Sends inbound datagrams to the next node as upstream payload.
- Sends downstream payload back to the remembered peer address.

This node is a chain head. Its upstream entry callbacks are disabled because packets arrive from external peers, not from a previous tunnel.

## Configuration Example

```json
{
  "name": "udp-listener",
  "type": "UdpListener",
  "settings": {
    "address": "0.0.0.0",
    "port": [5353, 853, 123],
    "large-send-buffer": true,
    "large-recv-buffer": true,
    "interface": "eth0",
    "fwmark": 10,
    "balance-group": "udp-public",
    "balance-interval": 30000,
    "multiport-backend": "socket",
    "whitelist": [
      "192.168.1.0/24",
      "2001:db8::/64"
    ],
    "blacklist": [
      "192.168.1.50/32"
    ]
  },
  "next": "next-node-name"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"UdpListener"`.

- `next` `(string)`
  The next node that should receive UDP lines and payloads.

### `settings`

- `address` `(string)`
  Bind address for the UDP socket.
  Common values are `"0.0.0.0"`, `"::"`, or a specific local address.

One of `port` or `port-range` is required.

- `port` `(number or array of numbers)`
  Listening port definition.
  Supported forms are:
  - a single number, for example `5353`
  - an array of explicit ports, for example `[5353, 853, 123]`

- `port-range` `(array[2])`
  A contiguous listening port range, for example `[20000, 20100]`.
  Use this only when every port between the two endpoints should be accepted.

## Optional `settings` Fields

- `interface` `(string)`
  Restricts the listener to a local network interface.
  Example: `"eth0"`

  On Linux this uses `SO_BINDTODEVICE`. On platforms without device binding, WaterWall falls back to binding the listener using the interface's IPv4 address.

- `fwmark` `(integer)`
  Linux-style socket mark.
  When the platform provides `SO_MARK`, this value is applied to the listening socket before bind.
  Default: not set

- `large-send-buffer` `(boolean or positive integer)`
  Sets `SO_SNDBUF` on UDP listener sockets.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged, including for dynamic association sockets. A positive integer sets the requested byte size directly.
  Default: `true`

- `large-recv-buffer` `(boolean or positive integer)`
  Sets `SO_RCVBUF` on UDP listener sockets.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged, including for dynamic association sockets. A positive integer sets the requested byte size directly.
  Default: `true`

- `balance-group` `(string)`
  Places this listener into a socket-manager balance group shared with other compatible listeners on the same port.

- `balance-interval` `(integer, milliseconds)`
  Sticky duration used by the balance group.

- `multiport-backend` `(string)`
  Backend used when `port-range` is configured.
  Supported values:
  - `"iptables"`
  - `"socket"`

  This field only matters for contiguous port ranges. Explicit `port` arrays use socket-per-port listening.

- `whitelist` `(array of strings)`
  List of allowed client IPs or CIDR ranges.
  Supports IPv4 and IPv6.

- `blacklist` `(array of strings)`
  List of blocked client IPs or CIDR ranges.
  Supports IPv4 and IPv6.

## Detailed Behavior

### Per-peer line model

UDP is connectionless, but `UdpListener` creates a pseudo-connection model for the chain.

For each unique remote peer address and port seen on a listening socket:

- a new WaterWall line is created
- the peer address is stored in line state
- later packets from the same peer reuse that same line until it expires

This gives later nodes a stable line abstraction even though the transport is UDP.

### Accept path

When a packet arrives and passes socket-manager filtering:

- the tunnel hashes the remote peer address and port
- it looks up an idle-table entry for that peer
- if no entry exists, a new line is created and upstream `init` is sent
- the packet is then forwarded upstream as payload

The line source context is filled from the peer socket address and marked as UDP.

### Data flow direction

- Peer to chain: received UDP datagram -> upstream payload to the next node
- Chain to peer: downstream payload -> UDP send to the remembered peer address

### Establishment semantics

A new peer line is created on the first packet. The line becomes established only when a downstream `est` callback reaches `UdpListener` from the next node.

### Pause behavior

`UdpListener` does not queue inbound datagrams while paused.

If the line is paused:

- incoming packets from that peer are dropped
- once resumed, new packets are forwarded again

This is important for users expecting TCP-like backpressure. In this tunnel, pause means drop, not buffer.

### Idle timeout behavior

Each peer line is tracked in an idle table.

Current timeouts:

- about `30 seconds` after the first packet for a newly created peer line
- about `300 seconds` for active peers after traffic continues

If the peer line expires, the line is finished upstream and destroyed.

### Dynamic endpoint provider

`UdpListener` also exposes a typed, in-process dynamic-endpoint provider to compatible protocol tunnels later in the
same chain. `Socks5Server` is one consumer of this capability. For a normal SOCKS5 service, use `TcpUdpListener`: its
internal `TcpListener` accepts the required TCP control connection and its internal `UdpListener` delegates this
provider. A bare `UdpListener` cannot provide a complete SOCKS5 entry by itself because it cannot accept that TCP
control connection.

This is not a JSON setting or an external `instance/api.c` message API. `Socks5Server` discovers it automatically from
its finalized preceding path; operators do not configure a provider node name.

The provider opens one dedicated UDP socket with an exclusive `port: 0` bind on the requesting event worker and returns
an opaque value handle (`owner_wid` plus generation), the kernel-assigned local address, and the actual local port. The
handle is valid only on its owner worker and may be closed repeatedly without affecting a newer endpoint.

Dynamic ingress uses the normal callback path: dynamic UDP socket -> `UdpListener` -> any wrapper such as
`TcpUdpListener` -> the configured next chain. Downstream replies return through that same endpoint to its pinned peer.
The dynamic socket honors the listener address, interface, `fwmark`, send/receive buffers, whitelist, and blacklist. It
does not use the configured static `port`, port range, balance group, or multiport backend.

Before a dynamic datagram can create or use its provider-owned line, its normalized
peer IP must equal the endpoint's expected peer IP. A configured nonzero source
port must also match exactly; source port zero pins the first valid sender and all
later ports must match that pin. Mismatching datagrams are silently dropped and
never close or message the TCP control association.

On quiesce, new endpoint opens and activations are refused. On each worker, the listener detaches endpoint WIO callbacks
before drain, removes the endpoint from its worker-local registry, and uses one idempotent close path to finish and
destroy any provider-owned dynamic line. This inventory is separate from the ordinary socket-manager peer table.

### Whitelist, blacklist, and balance behavior

Filtering and balancing are handled through the shared socket manager:

- `whitelist` limits which peer IPs are accepted by this listener
- `blacklist` rejects matching peer IPs for this listener
- `balance-group` enables sticky distribution between multiple listeners on the same port
- `multiport-backend` controls how `port-range` listeners are implemented

When both ACL lists are configured, a peer must match the whitelist, if any, and must not match the blacklist.

For `port` arrays, each element is treated as one explicit port. For example, `[5353, 853, 123]` listens only on those
three ports, not on the whole range between `123` and `5353`.

## Notes And Caveats

- `port` is parsed as a number or an array of explicit port numbers, and `port-range` is parsed as a two-item range array.
- `fwmark` and device binding are platform-dependent. `fwmark` is not available on Windows.
- Paused peer lines drop inbound datagrams instead of buffering them.
- Dynamic endpoints are internal capability plumbing for protocol tunnels; they are not additional public listening
  ports configured by `port` or `port-range`.
- For built-in SOCKS5 UDP service, configure `TcpUdpListener -> ... -> Socks5Server`, not a standalone `UdpListener` or
  `TcpListener` entry.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainHead` |
| `can_have_prev` | `false` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayerAnything` |
| `layer_group_prev_node` | `kNodeLayerNone` |
| `layer_group_next_node` | `kNodeLayerAnything` |
| `required_padding_left` | `0` bytes |
