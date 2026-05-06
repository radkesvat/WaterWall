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

This node acts like a chain end. Its downstream entry callbacks are disabled because the socket is created from upstream `init`.

## Configuration Example

```json
{
  "name": "udp-out",
  "type": "UdpConnector",
  "settings": {
    "address": "example.com",
    "port": "random(40000,40100)",
    "reuseaddr": true
  }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"UdpConnector"`.

### `settings`

- `address` `(string)`
  Destination address selection.

  Supported values in the current implementation:
  - a constant IPv4 address
  - a constant IPv6 address
  - a constant domain name
  - `"src_context->address"`
  - `"dest_context->address"`

- `port` `(number or string)`
  Destination port selection.

  Supported values in the current implementation:
  - a constant number such as `53`
  - a numeric string such as `"53"`
  - `"src_context->port"`
  - `"dest_context->port"`
  - `"random(x,y)"`

  The `random(x,y)` form chooses one random port in the inclusive range `[x, y]` during line initialization.

## Optional `settings` Fields

- `reuseaddr` `(boolean)`
  Enables `SO_REUSEADDR` on the created UDP socket.

## Detailed Behavior

### Socket setup

During upstream `init`, `UdpConnector`:

- creates a UDP socket
- enlarges the send and receive socket buffers to about `4 MB`
- binds the socket to `0.0.0.0:0`
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

### Domain resolution

If the selected address is a domain name, resolution is done synchronously during upstream `init`. If resolution fails, the line is finished immediately.

### Establishment semantics

There is no true UDP connect handshake here.

In the current implementation:

- upstream `init` creates the socket and configures the peer
- upstream payload can be sent immediately after that
- downstream `est` is only emitted when the first datagram is received from the remote peer

So from the previous node's point of view, this tunnel becomes established lazily on first reply, not on socket creation.

### Data flow direction

- Previous node to remote peer: upstream payload -> UDP send
- Remote peer to previous node: UDP receive -> downstream payload

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

If `port` uses `random(x,y)`, the destination port is chosen once during line initialization. After that, the line keeps using that selected port for its lifetime.

## Notes And Caveats

- Domain resolution in this path is synchronous.
- Paused reads drop inbound datagrams instead of buffering them.
- Downstream `est` is only triggered after the first packet is received from the remote side.
- Inbound datagrams from unexpected peers are ignored.
