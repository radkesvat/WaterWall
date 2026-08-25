<!--
Documentation version: 155
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TcpUdpListener.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/TcpUdpListener.mdx, and all files must keep the same documentation version.
-->

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
TcpUdpListener -> [optional middle tunnels] -> Socks5Server -> TcpUdpConnector
```

The next node must be able to handle both TCP and UDP line semantics if both transports are expected in production.

`TcpUdpListener` is the standard built-in entry node for `Socks5Server` with `udp: true`: its TCP child accepts the
SOCKS5 control connection, while its UDP child supplies the dynamic endpoint provider. A plain `TcpListener` supports
only SOCKS5 TCP/`CONNECT` and cannot satisfy `UDP ASSOCIATE`.

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
- `large-send-buffer` and `large-recv-buffer` are parsed by both child listeners; an explicit `false` also leaves kernel defaults unchanged for dynamic UDP child sockets.
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

## Dynamic UDP Endpoint Delegation

For a compatible protocol tunnel later in the same chain, including `Socks5Server`, `TcpUdpListener` delegates the typed
dynamic UDP endpoint provider capability to its internal `UdpListener`. `Socks5Server` discovers this provider
automatically from its finalized preceding path; no provider node name or JSON API setting is required. The internal
child still owns the dynamic socket, its worker-local endpoint registry, and every provider-created normal line; the
wrapper only preserves the normal chain path.

Ingress therefore remains:

```text
dynamic UDP child endpoint -> UdpListener child -> TcpUdpListener -> normal next chain
```

The wrapper uses the line source protocol on the downstream return path, so a dynamic UDP response is routed back to the
UDP child. The wrapper must not close, drain, or drive its child's endpoint lifecycle a second time.

The child enforces the endpoint's normalized expected peer IP before line
creation, a configured nonzero source port exactly, and a first-valid-packet pin
when the configured source port is zero. Mismatches are silent drops and do not
close or message the associated TCP control line.

## Notes And Caveats

- Both child listeners use the same port configuration. This node is not for different TCP and UDP port sets.
- The next node must tolerate both transports, or the config should route by protocol after this wrapper.
- Do not replace this node with `TcpListener` in a `Socks5Server` topology that enables UDP; `TcpListener` has no dynamic
  UDP provider.
- UDP pause semantics remain `UdpListener` semantics: paused UDP peer lines drop inbound datagrams instead of buffering them.
- Dynamic endpoint allocation uses an ephemeral UDP port from the internal child, not this wrapper's configured static
  TCP/UDP port.
- No payload bytes are added or removed, so the node requires no left padding.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainHead` |
| `can_have_prev` | `false` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayerNone` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `0` bytes |
