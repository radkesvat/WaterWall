<!--
Documentation version: 155
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TcpUdpConnector.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/TcpUdpConnector.mdx, and all files must keep the same documentation version.
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

- `domain-strategy`, `large-send-buffer`, `large-recv-buffer`, `interface`, `source-ip`, and `fwmark` are parsed by both child connectors where supported.
- `nodelay` and `fastopen` apply to the internal `TcpConnector`.
- `balance-mode` applies to the internal `UdpConnector`.

See `TcpConnector` and `UdpConnector` documentation for detailed destination selection and socket behavior.

## DNS behaviour

Resolving a hostname means looking up its IP address before connecting or sending.
The selected TCP or UDP connector first prepares the destination from this node's
settings. It performs a lookup only when that destination is an unresolved
hostname and local resolution is enabled. Literal IPs and already-resolved
destinations need no lookup.

This is the endpoint the connector will reach: the application target in a direct
chain, or the proxy server after a proxy client. Both children use the same DNS
policy. Without `dns-behaviour`, local resolution is enabled in `native` mode,
using the existing core or legacy `domain-strategy` preference.

Configure this lookup with `settings.dns-behaviour`:

```json
{
  "dns-behaviour": {
    "resolve": true,
    "mode": "direct",
    "strategy": "prefer-ipv4",
    "servers": ["203.0.113.53:53"]
  }
}
```

The address is a documentation placeholder; replace it with your resolver.

| Field | Meaning |
| --- | --- |
| `resolve` | Required boolean: `true` allows lookup of unresolved hostnames; `false` disables local lookup. |
| `mode` | `native` (default when enabled), `direct`, or `chain`. |
| `strategy` | `core-settings`, `accept-dns-returned-order`, `prefer-ipv4`, `prefer-ipv6`, `only-ipv4`, or `only-ipv6`; omission retains this consumer's existing selection default. |
| `servers` | 1–32 numeric IP, IP:port or [IPv6]:port endpoints; required for direct/chain and rejected for native. |
| `dns-next` | Nonempty DNS-entry name for chain only. |

`native` uses core DNS settings and the worker's shared resolver. It is the default
DNS transport when local resolution is enabled.

`direct` sends DNS queries through a private WaterWall TCP/UDP connector to the
servers you specify.

`chain` sends DNS queries through a selected chain. Use a path with encryption,
such as your VPN, to protect those queries; the mode alone does not encrypt them.
The DNS path must carry both UDP queries and TCP fallback. A route or lookup
failure does not switch to native DNS or another mode.

For `chain`, set `dns-next` to the name of a separate DNS branch that supports
both UDP and TCP. The branch must not already belong to another node. This node
has no default DNS branch; naming this node itself is not allowed.

The disabled form is exactly `"dns-behaviour": {"resolve": false}`. It rejects `mode`, `strategy`, `servers` and `dns-next`. Empty/null/non-object policies, unknown fields, numeric strategies and simultaneous same-scope legacy `domain-strategy` or `resolve-domains` are rejected. Existing legacy settings remain supported when this object is absent. `core-settings` chooses address preference only and never changes DNS transport.

With `resolve: false`, destination preparation still runs. Numeric or already-resolved destinations work; unresolved hostnames fail through the normal line/datagram path without an OS/native DNS fallback.

Both private TCP/UDP children use one authoritative provider, channel/cache owner and DNS-branch binding. This node has no default shared DNS entry; supply `dns-next` for chain mode.

See [DomainResolver](../../WaterWall-Docs/docs/02-noderefs/DomainResolver.mdx) for native, direct and protected-chain configuration examples and core option limits. This policy controls lookups owned by this node; it does not configure PTC fake DNS, TunDevice system DNS or every DNS source in the program.

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

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainEnd` &#124; `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `false` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayerNone` |
| `required_padding_left` | `0` bytes |

## UDP splice sending

UDP receives remain ordinary buffers. On an eligible Linux chain, UDP sends accept ordinary data or a real prefix plus a private-pipe body as one datagram to its explicit destination, including empty datagrams. Supported layouts use pipe-to-socket splice. Highly fragmented pipes, or failure to establish a safe fragment bound before sending, use a complete ordinary fallback before socket assembly. Oversized datagrams are rejected without splitting.

Pressure before assembly retains the existing drop policy, without a UDP retry queue. An incomplete splice or failed commit after priming retires only the affected socket; its associated normal lines close through their owners. Shared-socket peers can therefore close together. No truncated remainder is retried, and unrelated sockets remain active. Ordinary sends retain their existing error policy.

The flag does not bypass platform support, `misc.splice`, packet exclusion, or support from every node in the final expanded/merged chain. No end-to-end zero-copy or measured performance gain is promised.

Both internal connector nodes retain their capability flags. Eligibility includes both branches and inserted helpers, even for a TCP line. Protocol selection and UDP peer routing remain unchanged.
