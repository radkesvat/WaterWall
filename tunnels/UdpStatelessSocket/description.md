# UdpStatelessSocket Node

`UdpStatelessSocket` is a stateless UDP endpoint adapter. It binds one UDP socket, receives datagrams from any peer, and sends datagrams to the address currently stored in the line's routing context.

It exists primarily to support components such as `WireGuardDevice`, which need a lightweight UDP endpoint that can both send to a peer and accept packets from a peer without maintaining connection-oriented state.

## What It Does

- Binds a UDP socket on a configured local address and port.
- Receives UDP datagrams from any remote peer.
- Writes the sender address into the line's source routing context.
- Forwards received datagrams into the connected side of the chain.
- Sends outbound datagrams to the destination address stored in the line's routing context.
- Works in both directions using the same socket and the same payload path.

This node does not create one line per peer and does not keep session state. It is intentionally stateless.

## Typical Placement

A common layout is:

- `WireGuardDevice` or another packet-oriented node
- `UdpStatelessSocket`

or the reverse, depending on chain wiring.

`UdpStatelessSocket` is meant to sit at the UDP edge of a chain when a component needs raw stateless UDP send/receive capability rather than a stateful listener/connector model.

## Configuration Example

```json
{
  "name": "wg-udp-socket",
  "type": "UdpStatelessSocket",
  "settings": {
    "listen-address": "0.0.0.0",
    "listen-port": 51820,
    "interface": "eth0",
    "fwmark": 10,
    "source-ip": "192.0.2.10"
  }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"UdpStatelessSocket"`.

### `settings`

- `listen-address` `(string)`
  Local IP address to bind.

  This must be a valid IP address string.

- `listen-port` `(integer)`
  Local UDP port to bind.

  Valid range: `0` to `65535`

## Optional `settings` Fields

- `interface` `(string)`
  Restricts the UDP socket to a local network device where supported.
  On Linux this uses `SO_BINDTODEVICE`. On platforms without device binding, WaterWall falls back to binding the socket to the interface's IPv4 address when `source-ip` is not set.

- `fwmark` `(integer)`
  Linux-style socket mark.
  When the platform provides `SO_MARK`, this value is applied to the UDP socket before bind.
  Default: not set

- `source-ip` `(string)`
  Uses a specific local source IP for the UDP socket.
  For this stateless socket, `source-ip` is treated as an override for `listen-address`, because the same bound UDP socket is used for both receiving and sending.

## Detailed Behavior

### Stateless receive path

When a UDP datagram arrives on the bound socket:

- `UdpStatelessSocket` gets the worker packet line for the worker that owns the socket
- copies the sender address into that line's source routing context
- forwards the payload into the connected side of the chain

This means the next tunnel can inspect the sender address through the normal routing context fields.

### Stateless send path

When payload is sent through `UdpStatelessSocket`:

- the tunnel reads the destination address from `l->routing_context.dest_ctx`
- resolves the destination asynchronously if it is an unresolved domain
- converts the resolved/IP address context into a socket address
- sets the UDP socket's current peer address
- writes the datagram through the bound socket

So outbound routing is fully driven by the line's destination context rather than by any connection object owned by the tunnel.

### Listener and connector role

Although the implementation always binds a local UDP socket, the tunnel can act like either side of a peer exchange:

- it can receive packets from arbitrary peers like a listener
- it can also send packets to a chosen peer like a connector

That combination is why it is useful for `WireGuardDevice`, where the device may need to initiate contact to a peer or receive the first packet from a peer using the same stateless UDP socket.

### Chain integration

During prepare, `UdpStatelessSocket` decides where received packets should be written:

- if it is the last node in the chain, received packets are sent toward the previous node
- otherwise, received packets are sent toward the next node

This lets the same tunnel work in different adapter positions without changing its socket behavior.

### Worker behavior

The UDP socket is created on one worker loop.

If payload to be sent originates from a different worker:

- the send is scheduled onto the socket-owning worker
- the actual UDP write is then performed there

This preserves correct ownership of the socket while still allowing payload to come from any worker line.

### Connection semantics

`UdpStatelessSocket` does not maintain connection lifecycle in the usual sense.

Its init, est, fin, pause, and resume callbacks are effectively no-ops because the real purpose of the tunnel is datagram IO rather than stream/session management.

## Notes And Caveats

- `UdpStatelessSocket` is intended for stateless UDP traffic, especially around `WireGuardDevice`.
- The tunnel depends on valid routing context for outbound sends. In particular, `dest_ctx` must be initialized before sending payload.
- For packet lines, unresolved domain sends snapshot the domain and port for that datagram before resolving, because packet-line routing context is scratch metadata.
- This node does not create per-peer connection state.
- `fwmark` and device binding are platform-dependent. `fwmark` is not available on Windows.
- The JSON parser requires `listen-address` and `listen-port`; `source-ip` may override the effective local bind address.
