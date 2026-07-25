<!--
Documentation version: 109
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/IpOverrider.mdx, and both files must keep the same documentation version.
-->

# IpOverrider Node

`IpOverrider` rewrites packet IP addresses as traffic passes through the chain. A single instance can now apply independent overrides for upstream and downstream traffic, and for source and destination IP fields within each direction.

This node is a layer-3 packet tunnel. It does not create connections or sockets. It only inspects packets already flowing through the chain and rewrites configured address fields in place.

## What It Does

- Rewrites IPv4 source addresses on upstream traffic when configured.
- Rewrites IPv4 destination addresses on upstream traffic when configured.
- Rewrites IPv4 source addresses on downstream traffic when configured.
- Rewrites IPv4 destination addresses on downstream traffic when configured.
- Applies one node-level `only120` size gate before any configured rewrite.
- Applies one node-level `chance` gate before any configured rewrite.
- Marks packets for checksum recalculation after a rewrite.

## Typical Placement

`IpOverrider` is useful anywhere in a packet-oriented chain where you want to modify IP headers before handing traffic to the next stage.

Common uses include:

- rewriting both source and destination IPs without chaining multiple `IpOverrider` nodes
- applying different rewrite behavior to upstream and downstream packet flow
- testing or simulating NAT-like address changes inside a WaterWall chain

## Configuration Example

```json
{
  "name": "ip-rewrite",
  "type": "IpOverrider",
  "settings": {
    "up": {
      "source-ip": {
        "ipv4": "10.0.0.10"
      },
      "dest-ip": {
        "ipv4": "198.51.100.10"
      }
    },
    "down": {
      "source-ip": {
        "ipv4": "203.0.113.10"
      },
      "dest-ip": {
        "ipv4": "10.0.0.20"
      }
    }
  },
  "next": "next-node-name"
}
```

## Legacy Configuration Example

The old single-operation format is still accepted:

```json
{
  "name": "ip-rewrite-old",
  "type": "IpOverrider",
  "settings": {
    "direction": "up",
    "mode": "dest-ip",
    "ipv4": "198.51.100.10"
  }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"IpOverrider"`.

### `settings`

The current implementation supports two configuration styles:

- the new nested multi-rule format using `up` and/or `down`
- the legacy single-rule format using `direction` and `mode`

For the new format, you must provide at least one of:

- `settings.up.source-ip`
- `settings.up.dest-ip`
- `settings.down.source-ip`
- `settings.down.dest-ip`

Each present rule object must contain one of:

- `ipv4` `(string)`
- `ipv6` `(string)`

Important note: the current packet rewrite implementation only applies IPv4 changes at runtime. IPv6 values are parsed and stored, but the actual IPv6 header rewrite path is still disabled in code.

For the legacy format, required fields are:

- `direction` `(string)`
  Must be `"up"` or `"down"`.

- `mode` `(string)`
  Must be `"source-ip"` or `"dest-ip"`.

- `ipv4` or `ipv6` `(string)`
  The replacement IP address for the selected rule.

## Optional `settings` Fields

The root `settings` object may include:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `chance` | integer from `0` through `100` | `100` | Percentage chance that the node's complete rewrite action applies to an eligible packet. |
| `only120` | boolean | `false` | Restricts the complete rewrite action to IPv4 packets whose total IP length is `120` bytes or less. |

Both options belong directly inside `settings` in the new and legacy formats.
`chance` or `only120` inside a nested source or destination rule is invalid;
move it to `settings.chance` or `settings.only120`.

## Detailed Behavior

### Direction and field selection

The new configuration format lets one `IpOverrider` instance hold up to four independent rewrite rules:

- upstream source IP
- upstream destination IP
- downstream source IP
- downstream destination IP

When a packet flows upstream, only the configured upstream rules are checked. When a packet flows downstream, only the configured downstream rules are checked.

If both source and destination rules are configured for the same direction, both are applied to the same packet in that direction.

### `chance`

`chance` controls how often the complete node action runs. It is evaluated once
per eligible packet, not separately for each source or destination rule:

- `100` always applies the configured rules.
- `0` always forwards the packet unchanged.
- Values from `1` through `99` are percentages.

In this example, both upstream fields are rewritten together for approximately
25 percent of eligible packets; otherwise neither field is changed:

```json
{
  "name": "probabilistic-ip-rewrite",
  "type": "IpOverrider",
  "settings": {
    "chance": 25,
    "up": {
      "source-ip": {
        "ipv4": "10.0.0.10"
      },
      "dest-ip": {
        "ipv4": "198.51.100.10"
      }
    }
  },
  "next": "next-node-name"
}
```

### `only120`

`only120` is a size gate for the complete node action. When it is `true`, all
configured rewrites run together for IPv4 packets whose total IP length is
`120` bytes or less. Larger IPv4 packets are forwarded unchanged.

```json
{
  "name": "small-packet-ip-rewrite",
  "type": "IpOverrider",
  "settings": {
    "only120": true,
    "up": {
      "source-ip": {
        "ipv4": "10.0.0.10"
      },
      "dest-ip": {
        "ipv4": "198.51.100.10"
      }
    }
  },
  "next": "next-node-name"
}
```

### Combining `only120` and `chance`

For every upstream or downstream packet, `IpOverrider` evaluates its root-level
gates before checking any source or destination rule:

- If `only120` is enabled and the IPv4 total length is greater than `120`, the
  complete node action is skipped.
- Otherwise, `settings.chance` is evaluated exactly once for the packet. If the
  chance does not happen, the complete node action is skipped.
- When both gates pass, every configured rule for the packet direction is
  evaluated.

When either gate skips the node action, the packet is forwarded unchanged,
IPv4 address-array cursors are not advanced, and this node does not request
checksum recalculation.

### Packet flow behavior

`IpOverrider` does not terminate the chain and does not buffer packets.

- upstream payload is rewritten in place and then forwarded to the next node
- downstream payload is rewritten in place and then forwarded to the previous node

If no rule exists for a given direction, packets in that direction simply pass through unchanged.

### Checksum behavior

Whenever an IPv4 rewrite is applied, `IpOverrider` sets the line flag that requests checksum recalculation later in the packet pipeline.

This keeps downstream packet writers or adapters responsible for final checksum updates.

## Notes And Caveats

- The current runtime rewrite path only modifies IPv4 packets.
- IPv6 addresses are parsed and stored, but IPv6 header rewriting is not enabled yet.
- A single tunnel instance can now replace what previously required multiple chained `IpOverrider` nodes.
- The legacy `direction` plus `mode` configuration is still supported for backward compatibility.
