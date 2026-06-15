# TcpUdpListener Node

`TcpUdpListener` is a chain-head wrapper around `TcpListener` and `UdpListener`. It registers both child listeners with
the same listener settings so TCP and UDP traffic can be accepted on the same address and port set, then forwards both
transports into one shared next node.

It does not create connection lines itself. The internal `TcpListener` owns TCP line creation and destruction, and the
internal `UdpListener` owns UDP peer-line creation and destruction.

## What It Does

- creates one internal `TcpListener`
- creates one internal `UdpListener`
- passes the same `settings` object to both child listeners
- forwards upstream `Init`, `Payload`, `Pause`, `Resume`, `Est`, and `Finish` from either child listener to the next node
- routes downstream callbacks back to the correct child listener using the line source protocol flags
- includes both child listeners in the chain so their line states are allocated normally

## Typical Placement

`TcpUdpListener` is used at the beginning of a chain when one service should receive both TCP and UDP on the same port or
port set:

```text
TcpUdpListener -> SpeedTestServer
TcpUdpListener -> SniffRouter -> ...
TcpUdpListener -> SomeProtocolServer -> ...
```

The next node must be able to handle both TCP and UDP line semantics if both transports are expected in production.

## Configuration Example

```json
{
  "name": "mixed-listener",
  "type": "TcpUdpListener",
  "settings": {
    "address": "0.0.0.0",
    "port": [443, 8443],
    "nodelay": true,
    "large-send-buffer": true,
    "large-recv-buffer": true,
    "interface": "eth0",
    "fwmark": 10,
    "balance-group": "public-mixed",
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
  A user-chosen name for this wrapper node.

- `type` `(string)`
  Must be exactly `"TcpUdpListener"`.

- `next` `(string)`
  The next node that should receive both accepted TCP lines and UDP peer lines.

### `settings`

The `settings` object is passed to both internal child listeners.

- `address` `(string)`
  Bind address for both TCP and UDP listeners.

One of `port` or `port-range` is required.

- `port` `(number or array of numbers)`
  One explicit port or a list of explicit ports used by both TCP and UDP.

- `port-range` `(array[2])`
  A contiguous port range used by both TCP and UDP.

## Optional `settings` Fields

Most options are inherited directly from `TcpListener` and `UdpListener`:

- `nodelay` applies to the internal TCP listener.
- `large-send-buffer` and `large-recv-buffer` are parsed by both child listeners.
- `interface`, `fwmark`, `balance-group`, `balance-interval`, `multiport-backend`, `whitelist`, and `blacklist` are passed to both child listeners.

See `TcpListener` and `UdpListener` documentation for the exact behavior of each setting.

## Lifecycle And Direction Rules

The internal child listeners are the real socket adapters:

- TCP accept or UDP first packet creates the line in the child listener.
- Child upstream callbacks enter `TcpUdpListener`.
- `TcpUdpListener` forwards those callbacks with `tunnelNextUpStream*`.
- Downstream callbacks from the next node enter `TcpUdpListener`.
- `TcpUdpListener` selects the internal TCP or UDP listener from `line->routing_context.src_ctx`.
- The selected child listener handles downstream writes, pauses, resumes, establishment, and finish.

`TcpUdpListener` has no per-line state and never calls `lineDestroy()`.

## Notes And Caveats

- Both child listeners use the same port configuration. This node is not for different TCP and UDP port sets.
- The next node must tolerate both transports, or the config should route by protocol after this wrapper.
- UDP pause semantics remain `UdpListener` semantics: paused UDP peer lines drop inbound datagrams instead of buffering them.
- No payload bytes are added or removed, so the node requires no left padding.
