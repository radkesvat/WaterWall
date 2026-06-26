<!--
Documentation version: 106
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
- Applies rule-local filters such as `chance` and `only120`.
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
        "ipv4": "198.51.100.10",
        "only120": true
      }
    },
    "down": {
      "source-ip": {
        "ipv4": "203.0.113.10",
        "chance": 100
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
    "ipv4": "198.51.100.10",
    "chance": 100,
    "only120": false
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

Each rule object in the new format, and the top-level legacy rule format, may include:

- `chance` `(integer)`
  Percentage chance that the rule should be applied.

  Accepted range: `0` to `100`

  Current implementation detail:
  - `100` means always apply
  - `0` means never apply
  - if omitted, the rule always applies

- `only120` `(boolean)`
  If `true`, the rule is only applied to IPv4 packets whose total IP length is `120` bytes or less.

  Default: `false`

## Detailed Behavior

### Direction and field selection

The new configuration format lets one `IpOverrider` instance hold up to four independent rewrite rules:

- upstream source IP
- upstream destination IP
- downstream source IP
- downstream destination IP

When a packet flows upstream, only the configured upstream rules are checked. When a packet flows downstream, only the configured downstream rules are checked.

If both source and destination rules are configured for the same direction, both are applied to the same packet in that direction.

### Rule evaluation

For each applicable rule:

- if the rule is not present, nothing happens
- if `chance` causes the rule to be skipped, nothing happens
- if `only120` is enabled and the IPv4 packet length is greater than `120`, nothing happens
- otherwise the selected IP field is replaced and checksum recalculation is requested

Rules are evaluated independently, so one rule in a direction can apply while another one in the same direction is skipped.

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
