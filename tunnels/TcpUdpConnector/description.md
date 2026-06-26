<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TcpUdpConnector.mdx, and both files must keep the same documentation version.
-->

# TcpUdpConnector Node

`TcpUdpConnector` is a chain-end wrapper around `TcpConnector` and `UdpConnector`. It lets one chain end connect TCP
lines through `TcpConnector` and UDP lines through `UdpConnector` while using one shared connector settings object.

It does not create or destroy connection lines itself. The previous chain head or bridge owns line creation, and the
selected internal connector owns the real outbound socket state for that line.

## What It Does

- creates one internal `TcpConnector`
- creates one internal `UdpConnector`
- passes the same `settings` object to both child connectors
- selects the child connector during upstream `Init`
- remembers the selected child connector in this node's per-line state
- forwards upstream `Payload`, `Pause`, `Resume`, `Est`, and `Finish` to that selected child
- forwards downstream callbacks from either child connector back to the previous node
- includes both child connectors in the chain so their line states and lifecycle callbacks are handled normally

## Typical Placement

`TcpUdpConnector` is used at the end of a chain when one outbound configuration should support both TCP and UDP:

```text
Socks5Server -> TcpUdpConnector
TcpUdpListener -> SniffRouter -> TcpUdpConnector
PacketsToConnection -> TcpUdpConnector
```

The previous node must set either the destination protocol or the source protocol to TCP or UDP.

## Configuration Example

```json
{
  "name": "mixed-out",
  "type": "TcpUdpConnector",
  "settings": {
    "address": "dest_context->address",
    "port": "dest_context->port",
    "domain-strategy": "prefer-ipv4",
    "reuseaddr": true,
    "nodelay": true,
    "fastopen": false,
    "large-send-buffer": true,
    "large-recv-buffer": true,
    "interface": "eth0",
    "fwmark": 10,
    "balance-mode": "connection"
  }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this wrapper node.

- `type` `(string)`
  Must be exactly `"TcpUdpConnector"`.

This node is a chain end and must not have `next`.

### `settings`

The `settings` object is passed to both internal child connectors.

- `address` `(string)`
  Destination address rule. It can be a constant IP/domain, `"src_context->address"`, or `"dest_context->address"`.

- `port` `(number or string)`
  Destination port rule. It can be a constant port, `"src_context->port"`, or `"dest_context->port"`.

Alternatively, use the `addresses` array supported by `TcpConnector` and `UdpConnector`.

## Optional `settings` Fields

Most options are inherited directly from `TcpConnector` and `UdpConnector`:

- `domain-strategy`, `large-send-buffer`, `large-recv-buffer`, `interface`, `source-ip`, `fwmark`, and `reuseaddr` are parsed by both child connectors where supported.
- `nodelay` and `fastopen` apply to the internal `TcpConnector`.
- `balance-mode` applies to the internal `UdpConnector`.

See `TcpConnector` and `UdpConnector` documentation for detailed destination selection and socket behavior.

## Protocol Selection

During upstream `Init`, `TcpUdpConnector` first checks `line->routing_context.dest_ctx`.

- exact TCP destination protocol selects `TcpConnector`
- exact UDP destination protocol selects `UdpConnector`
- unsupported or ambiguous destination protocol flags are rejected

If the destination context has no protocol flags, `TcpUdpConnector` falls back to `line->routing_context.src_ctx`. This
keeps simple TCP-in-to-TCP-out and UDP-in-to-UDP-out chains usable with constant outbound destinations.

The selected child connector is stored in this node's line state. Later upstream callbacks use the stored child instead
of re-reading `dest_ctx`, because the selected connector may rewrite the destination context during its own init.

## Lifecycle And Direction Rules

The internal child connectors are the real socket adapters:

- the previous node sends upstream `Init` into `TcpUdpConnector`
- `TcpUdpConnector` selects and initializes one child connector
- later upstream callbacks are forwarded to that same child connector
- downstream callbacks from the child connector enter `TcpUdpConnector`
- `TcpUdpConnector` forwards downstream callbacks with `tunnelPrevDownStream*`

`TcpUdpConnector` has only a small selected-child line state. It clears that state before forwarding downstream `Finish`
or before forwarding upstream `Finish` into the selected child. It never calls `lineDestroy()`.

## Notes And Caveats

- Both child connectors receive the same settings. This node is not for separate TCP and UDP destination settings.
- If a previous node can set destination protocol, that protocol wins over source protocol.
- If neither source nor destination has an exact TCP or UDP protocol flag, the line is rejected as a configuration or routing error.
- No payload bytes are added or removed, so the node requires no left padding.
