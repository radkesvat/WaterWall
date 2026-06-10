# UdpConnector Node

`UdpConnector` is an outbound UDP client node. It creates a local UDP socket, chooses a destination address and port, and forwards datagrams between the previous node and the selected remote peer.

In practice, this node is used at the end of a chain.

## What It Does

- Creates a UDP socket bound to an ephemeral local port.
- Chooses a destination address and destination port.
- Resolves a domain name if needed.
- Forwards upstream payload from the previous node to the remote UDP peer.
- Forwards datagrams received from the remote UDP peer back downstream.
- Drops datagrams that arrive from a peer other than the selected remote endpoint.
- Tracks the UDP line with idle timeouts.
- Applies optional socket options such as `SO_REUSEADDR`, `SO_MARK`, device binding, and source-IP binding when supported by the platform.

This node acts like a chain end. Its downstream entry callbacks are disabled because the socket is created from upstream `init`.

## Configuration Example

```json
{
  "name": "udp-out",
  "type": "UdpConnector",
  "settings": {
    "address": "example.com",
    "port": "random(40000,40100)",
    "reuseaddr": true,
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
    "reuseaddr": true,
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

- `reuseaddr` `(boolean)`
  Enables `SO_REUSEADDR` on the created UDP socket.

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

- creates a UDP socket
- applies the configured send and receive socket buffer sizes
- applies optional `interface`, `fwmark`, and `reuseaddr` socket options
- binds the socket to `source-ip:0` when `source-ip` is configured, otherwise to the wildcard address for the selected address family
- starts reading immediately
- stores line state and idle tracking for the new socket
- computes the destination address and port for this line
- resolves the domain if needed
- stores the destination as the socket peer address

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

When `addresses` is used, the same selection rules apply inside each array element.
In the default `"connection"` balance mode, the connector first picks one destination object by weight, then resolves that chosen object's `address` and `port` for the line.
In `"packet"` balance mode, the weighted choice happens for every upstream payload packet, but each destination object's resolved context is cached on the WaterWall line after first use.

`"packet"` mode still uses one UDP socket per WaterWall line, so all selected packet destinations must be compatible with that socket's address family. For example, do not mix IPv4-only and IPv6-only targets in one packet-balanced list unless the selected socket family can send to all of them.

### Domain resolution

If the selected address is a domain name, resolution is submitted asynchronously on the line's worker during upstream `init`. Payloads that arrive before resolution completes are kept in a bounded pre-connect queue. If resolution fails, the line is finished immediately.

In `"packet"` balance mode, domain names inside packet-balanced destination objects are resolved lazily per destination object on each WaterWall line. The first packet that selects an unresolved domain starts one async DNS request for that destination and packets for that destination wait in a bounded queue. After the destination is resolved, that resolved address context is reused for later packets on the same line; there is no time-based DNS cache and no per-packet DNS request.

### Establishment semantics

There is no true UDP connect handshake here.

In the current implementation:

- upstream `init` creates the socket and configures the peer
- downstream `est` is emitted after the UDP socket is successfully created and ready to send
- upstream payload can be sent immediately after that

So from the previous node's point of view, this tunnel becomes established when the local UDP socket is ready, not after
a remote reply.

### Data flow direction

- Previous node to remote peer: upstream payload -> UDP send
- Remote peer to previous node: UDP receive -> downstream payload

In `"connection"` balance mode, inbound datagrams are accepted only from the single selected remote peer.
In `"packet"` balance mode, inbound datagrams are accepted from the connector socket so replies from any target selected by packet balancing can return even if packets are answered out of order.

### Pause behavior

When paused, `UdpConnector` does not queue received datagrams.

If a datagram arrives while reads are paused:

- that datagram is dropped
- reads continue again after resume

### Idle timeout behavior

Each UDP line is tracked in an idle table.

Current timeouts:

- about `30 seconds` after initialization
- about `300 seconds` after continuing traffic

If the UDP line expires, the socket is closed and downstream `finish` is sent to the previous node.

### Random destination port selection

If `port` uses `random(x,y)` with `"connection"` balance mode, the destination port is chosen once during line initialization. After that, the line keeps using that selected port for its lifetime.
With `"packet"` balance mode, a `random(x,y)` port is selected when that destination object is first materialized on the line, then reused for later packets that choose the same destination object.

## Notes And Caveats

- Domain resolution in this path is asynchronous and keeps pre-resolution datagrams queued up to the connector queue limit.
- `fwmark` and device binding are platform-dependent. `fwmark` is not available on Windows.
- Paused reads drop inbound datagrams instead of buffering them.
- Downstream `est` is triggered after the local UDP socket is created and ready.
- Inbound datagrams from unexpected peers are ignored in `"connection"` mode. In `"packet"` mode, datagrams received on the connector socket are accepted so replies from any packet-balanced target can return.
