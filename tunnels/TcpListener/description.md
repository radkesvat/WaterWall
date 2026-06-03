# TcpListener Node

`TcpListener` is a TCP server node. It listens for inbound TCP connections, creates a new line for each accepted client, and passes that line upstream to the next node in the chain.

In practice, this node is used at the beginning of a chain.

## What It Does

- Binds and listens on one TCP port or a TCP port range.
- Accepts incoming client connections.
- Creates a WaterWall line for each accepted socket.
- Sends data received from the client to the next node.
- Sends downstream data from the next node back to the client socket.
- Applies optional accept-time filters such as whitelist/blacklist checks and balance groups.

This node is a chain head. Its upstream entry callbacks are disabled because connections are created by external clients, not by a previous tunnel.

## Configuration Example

```json
{
  "name": "inbound-listener",
  "type": "TcpListener",
  "settings": {
    "address": "0.0.0.0",
    "port": 443,
    "nodelay": true,
    "large-send-buffer": true,
    "large-recv-buffer": true,
    "interface": "eth0",
    "fwmark": 10,
    "balance-group": "public-443",
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
  Must be exactly `"TcpListener"`.

- `next` `(string)`
  The next node that should receive accepted TCP lines.

### `settings`

- `address` `(string)`
  The bind address for the listener.
  Common values are `"0.0.0.0"`, `"::"`, or a specific local address.

- `port` `(number or array[2])`
  The listening port definition.
  Supported forms in the current implementation are:
  - a single number, for example `443`
  - a two-item array, for example `[40000, 40100]`

  Older string-style examples such as `"40000-40100"` are not what the current code parses.

## Optional `settings` Fields

- `nodelay` `(boolean)`
  Enables `TCP_NODELAY` on accepted sockets.
  Default: `false`

- `large-send-buffer` `(boolean or positive integer)`
  Sets `SO_SNDBUF` on accepted TCP sockets.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged. A positive integer sets the requested byte size directly.
  Default: `false`, or `true` when this option is omitted and the chain contains `MuxClient` or `MuxServer`.

- `large-recv-buffer` `(boolean or positive integer)`
  Sets `SO_RCVBUF` on accepted TCP sockets.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged. A positive integer sets the requested byte size directly.
  Default: `false`, or `true` when this option is omitted and the chain contains `MuxClient` or `MuxServer`.

- `interface` `(string)`
  Restricts the listener to a local network interface.
  Example: `"eth0"`

  On Linux this uses `SO_BINDTODEVICE`. On platforms without device binding, WaterWall falls back to binding the listener using the interface's IPv4 address.

- `fwmark` `(integer)`
  Linux-style socket mark.
  When the platform provides `SO_MARK`, this value is applied to the listening socket before bind.
  Default: not set

- `balance-group` `(string)`
  Places this listener into a balance group with other listeners on the same port.
  New clients are distributed between matching listeners, and repeat clients stay sticky for a period of time.

- `balance-interval` `(integer, milliseconds)`
  Sticky duration for a client entry inside a balance group.
  After this interval expires, the next connection from that client can be routed to a different listener in the same group.

- `multiport-backend` `(string)`
  Backend used when `port` is a range.
  Supported values:
  - `"iptables"`
  - `"socket"`

  This field only matters for port ranges.

- `whitelist` `(array of strings)`
  List of allowed client IPs or CIDR ranges.
  Supports IPv4 and IPv6.
  Example:

  ```json
  ["10.0.0.0/8", "2001:db8::/64"]
  ```

- `blacklist` `(array of strings)`
  List of blocked client IPs or CIDR ranges.
  Supports IPv4 and IPv6.
  Example:

  ```json
  ["10.0.0.13/32", "2001:db8:bad::/64"]
  ```

## Detailed Behavior

### Accept path

When a TCP client connects, `TcpListener`:

- attaches the accepted socket to a worker loop
- creates a new line
- stores line state for that connection
- fills routing information for the new line
- notifies the next node with upstream `init`
- starts reading from the client socket

The line's source context is populated from the accepted connection. In the current implementation, the peer IP is recorded and the local port that accepted the connection is stored in the source context port field.

### Data flow direction

- Client to chain: socket read -> upstream payload to the next node
- Chain to client: downstream payload -> socket write

That means the next node should expect to receive traffic from accepted clients and should send responses back downstream.

### Flow control and buffering

`TcpListener` implements backpressure for slow client sockets:

- if a write cannot complete immediately, outgoing buffers are queued
- once the queue grows beyond `1 KB`, the next node is paused
- when the socket becomes writable again, the node resumes the next node
- if the queued data grows beyond `16 MB`, the connection is closed

This protects the process from unbounded buffering when the client is slow or stalled.

### Idle timeout behavior

Each accepted connection is tracked in an idle table.

- a newly accepted connection starts with a `5 second` timeout
- active connections are refreshed to about `300 seconds`
- if the connection expires, the socket and line are closed

### Balance groups

If multiple listeners share the same `balance-group` and port, the socket manager selects one of them for a new client and remembers that choice using a hash of the client IP. During `balance-interval`, later connections from the same client IP stay pinned to the same listener.

### Whitelist and blacklist matching

If `whitelist` is present, only matching client IPs are accepted by this listener. If multiple listeners are registered on the same port, another listener may still receive the same connection if its filter matches and this listener's filter does not.

If `blacklist` is present, matching client IPs are rejected by this listener. When both lists are configured, a client must match the whitelist, if any, and must not match the blacklist.

### Multiport backend notes

For port ranges, the runtime can either:

- create one listening socket per port with the `socket` backend
- use a single main socket plus redirection rules with the `iptables` backend

If you want `iptables` specifically, set it explicitly.

## Notes And Caveats

- The current parser expects `port` as a number or a two-item array, not a string range.
- `fwmark` and device binding are platform-dependent. `fwmark` is not available on Windows.
- This node is designed to be used as an inbound entry point in the chain.
