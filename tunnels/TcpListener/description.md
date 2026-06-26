<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TcpListener.mdx, and both files must keep the same documentation version.
-->

# TcpListener Node

`TcpListener` is a TCP server node. It listens for inbound TCP connections, creates a new line for each accepted client, and passes that line upstream to the next node in the chain.

In practice, this node is used at the beginning of a chain.

## What It Does

- Binds and listens on one TCP port, several explicit TCP ports, or a TCP port range.
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
    "port": [443, 80, 2083],
    "nodelay": true,
    "large-send-buffer": true,
    "large-recv-buffer": true,
    "interface": "eth0",
    "fwmark": 10,
    "balance-group": "public-443",
    "balance-interval": 30000,
    "initial-idle-timeout-ms": 5000,
    "active-idle-timeout-ms": 300000,
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

One of `port` or `port-range` is required.

- `port` `(number or array of numbers)`
  The listening port definition.
  Supported forms are:
  - a single number, for example `443`
  - an array of explicit ports, for example `[443, 80, 2083]`

- `port-range` `(array[2])`
  A contiguous listening port range, for example `[40000, 40100]`.
  Use this only when every port between the two endpoints should be accepted.

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

- `initial-idle-timeout-ms` `(positive integer, milliseconds)`
  Idle timeout for a newly accepted TCP connection before any listener-side payload activity is seen.
  Default: `5000`

- `active-idle-timeout-ms` `(positive integer, milliseconds)`
  Idle timeout after the listener sees activity on the connection.
  Default: `300000`

  For chains such as `TcpListener -> TlsServer`, this is still listener-side activity, not proof that TLS has completed.
  A client that sends a partial TLS record can move to this timeout while `TlsServer` is still waiting for more handshake
  bytes. When using `TlsServer` fallback for probe resistance, tune this value together with the public TLS service you
  are trying to resemble.

- `multiport-backend` `(string)`
  Backend used when `port-range` is configured.
  Supported values:
  - `"iptables"`
  - `"socket"`

  This field only matters for contiguous port ranges. Explicit `port` arrays use socket-per-port listening.

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

- a newly accepted connection starts with the configured initial timeout, `5 seconds` by default
- active connections are refreshed to the configured active timeout, `300 seconds` by default
- if the connection expires, the socket and line are closed

The initial and active timeout values are configurable with `initial-idle-timeout-ms` and `active-idle-timeout-ms`.
These are stack-level timing signals. If the listener feeds a probe-resistant TLS chain and fallback points to a public
TLS service, keep Waterwall and that service synchronized enough that stalled-client close timing is not itself a
fingerprint.

### Balance groups

If multiple listeners share the same `balance-group` and port, the socket manager selects one of them for a new client and remembers that choice using a hash of the client IP. During `balance-interval`, later connections from the same client IP stay pinned to the same listener.

### Whitelist and blacklist matching

If `whitelist` is present, only matching client IPs are accepted by this listener. If multiple listeners are registered on the same port, another listener may still receive the same connection if its filter matches and this listener's filter does not.

If `blacklist` is present, matching client IPs are rejected by this listener. When both lists are configured, a client must match the whitelist, if any, and must not match the blacklist.

### Multiport backend notes

For `port-range`, the runtime can either:

- create one listening socket per port with the `socket` backend
- use a single main socket plus redirection rules with the `iptables` backend

If you want `iptables` specifically, set it explicitly.

For `port` arrays, each element is treated as one explicit port. For example, `[443, 80, 2083]` listens only on those
three ports, not on the whole range between `80` and `2083`.

## Notes And Caveats

- The parser expects `port` as a number or an array of explicit port numbers, or `port-range` as a two-item range array.
- `fwmark` and device binding are platform-dependent. `fwmark` is not available on Windows.
- This node is designed to be used as an inbound entry point in the chain.
