<!--
Documentation version: 107
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/SoftIpLimiter.mdx, and both files must keep the same documentation version.
-->

# SoftIpLimiter Node

`SoftIpLimiter` is a stream middle tunnel that limits how many source IP addresses may use the same early VLESS or
Trojan identity at the same time.

It is intended to sit immediately before the clear protocol parser:

- before `VlessServer` when `identifier` is `vless`
- before `TrojanServer` when `identifier` is `trojan`

The node reads only the minimum early bytes needed to identify the connection, checks the source IP against an in-memory
table, and then forwards the original buffered bytes unchanged. It does not authenticate users, parse destinations, add
headers, remove headers, or rewrite payload. `VlessServer` or `TrojanServer` must still run after it and perform the real
protocol authentication.

## What It Does

- Extracts a 64-bit internal key from the early VLESS UUID or Trojan SHA224 identity.
- Tracks up to `6` source IP addresses per identity.
- Treats multiple live connections from the same source IP as one IP row.
- Keeps a reference count for live lines from the same identity and source IP.
- Updates each IP row's `last-seen-ms` on every upstream and downstream payload.
- Prunes stale IP rows before admission and before forwarding payload.
- Gracefully closes a line if its IP row was removed or expired before its next payload transfer.
- Logs rejected connections only when `verbose` is enabled.

## Typical Placement

VLESS over plain TCP for local or test deployments:

```text
TcpListener -> SoftIpLimiter(identifier=vless) -> VlessServer -> TcpUdpConnector
```

VLESS over TLS for public deployments:

```text
TcpListener -> TlsServer -> SoftIpLimiter(identifier=vless) -> VlessServer -> TcpUdpConnector
```

Trojan over TLS:

```text
TcpListener -> TlsServer -> SoftIpLimiter(identifier=trojan) -> TrojanServer -> TcpUdpConnector
```

Important:

- Place `SoftIpLimiter` after any encryption or transport wrapper that hides the VLESS/Trojan bytes.
- Place it before `VlessServer` or `TrojanServer`, not after them.
- Use `identifier: "vless"` only before `VlessServer`.
- Use `identifier: "trojan"` only before `TrojanServer`.
- For public Trojan deployments, TLS must already be terminated before `SoftIpLimiter`, usually by `TlsServer`.
- This node is stream-only. Do not use it as a packet tunnel or as a packet-line policy node.

## Configuration Examples

### VLESS IP limit

Allow each VLESS UUID to be active from at most two source IP addresses at a time:

```json
{
  "name": "soft-ip-limit",
  "type": "SoftIpLimiter",
  "settings": {
    "identifier": "vless",
    "simultaneous-user-limit": 2,
    "tolerance-ms": 30000,
    "verbose": false
  },
  "next": "vless-server"
}
```

Example chain:

```json
[
  {
    "name": "listener",
    "type": "TcpListener",
    "settings": {
      "address": "0.0.0.0",
      "port": 443
    },
    "next": "tls-server"
  },
  {
    "name": "tls-server",
    "type": "TlsServer",
    "settings": {
      "cert-file": "/etc/waterwall/fullchain.pem",
      "key-file": "/etc/waterwall/privkey.pem"
    },
    "next": "soft-ip-limit"
  },
  {
    "name": "soft-ip-limit",
    "type": "SoftIpLimiter",
    "settings": {
      "identifier": "vless",
      "simultaneous-user-limit": 2,
      "tolerance-ms": 30000
    },
    "next": "vless-server"
  },
  {
    "name": "vless-server",
    "type": "VlessServer",
    "settings": {
      "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
      "connect": true,
      "udp": true
    },
    "next": "outbound"
  },
  {
    "name": "outbound",
    "type": "TcpUdpConnector",
    "settings": {
      "address": "dest_context->address",
      "port": "dest_context->port"
    }
  }
]
```

### Trojan IP limit

Allow each Trojan password identity to be active from one source IP address at a time:

```json
{
  "name": "trojan-soft-ip-limit",
  "type": "SoftIpLimiter",
  "settings": {
    "identifier": "trojan",
    "simultaneous-user-limit": 1,
    "tolerance-ms": 45000,
    "verbose": true
  },
  "next": "trojan-server"
}
```

Typical Trojan chain:

```json
[
  {
    "name": "listener",
    "type": "TcpListener",
    "settings": {
      "address": "0.0.0.0",
      "port": 443
    },
    "next": "tls-server"
  },
  {
    "name": "tls-server",
    "type": "TlsServer",
    "settings": {
      "cert-file": "/etc/waterwall/fullchain.pem",
      "key-file": "/etc/waterwall/privkey.pem"
    },
    "next": "trojan-soft-ip-limit"
  },
  {
    "name": "trojan-soft-ip-limit",
    "type": "SoftIpLimiter",
    "settings": {
      "identifier": "trojan",
      "simultaneous-user-limit": 1,
      "tolerance-ms": 45000,
      "verbose": true
    },
    "next": "trojan-server"
  },
  {
    "name": "trojan-server",
    "type": "TrojanServer",
    "settings": {
      "password": "secret-password",
      "connect": true,
      "udp": true
    },
    "next": "outbound"
  }
]
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen node name.

- `type` `(string)`
  Must be exactly `"SoftIpLimiter"`.

- `next` `(string)`
  Required. Accepted traffic is forwarded to this node.

### `settings`

`settings` must be a non-empty object.

- `identifier` `(string)`
  Required. Must be exactly `vless` or `trojan`.

  `vless` reads the VLESS version byte and UUID from the beginning of the upstream stream. `trojan` reads the first
  56 ASCII hex characters of the Trojan password hash.

- `simultaneous-user-limit` `(integer)`
  Required. Number of distinct source IP addresses allowed for one identity at the same time.

  Minimum: `1`

  Maximum: `6`

- `tolerance-ms` `(integer, milliseconds)`
  Required. An IP row whose last payload activity is older than this value is considered stale and may be removed.

  Minimum: `1`

## Optional `settings` Fields

- `verbose` `(boolean)`
  Enables warning logs for rejected admissions and active payload closures.

  Default: `false`

## Identity Extraction

### VLESS mode

In `vless` mode, the first upstream bytes must start with a VLESS v0 credential prefix:

```text
version:  1 byte, must be 00
uuid:     16 raw UUID bytes
```

The 16 UUID bytes are reduced to the internal 64-bit key with `calcHashBytes(uuid, 16)`.

The bytes are not consumed or rewritten. After admission, the complete buffered stream is forwarded unchanged to
`VlessServer`.

### Trojan mode

In `trojan` mode, the first upstream bytes must begin with the standard Trojan password hash:

```text
password hash: 56 ASCII hex bytes, hex(SHA224(password))
```

`SoftIpLimiter` validates and decodes the 56 hex characters, then reduces the 28 SHA224 bytes to the internal 64-bit key
with `calcHashBytes(sha224, 28)`.

The bytes are not consumed or rewritten. After admission, the complete buffered stream is forwarded unchanged to
`TrojanServer`.

## Limit Behavior

The limit is per identity, not global for the node.

For example, with:

```json
{
  "identifier": "vless",
  "simultaneous-user-limit": 2,
  "tolerance-ms": 30000
}
```

one UUID may be used by:

- `203.0.113.10`
- `203.0.113.11`

If a third IP tries to use the same UUID while both rows are still active, the new connection is rejected. A different
UUID has its own independent IP list.

Multiple connections from the same source IP and same identity count as one IP address. The row keeps a reference count,
so the row is removed only after the last live line for that source IP is released or after it becomes stale.

## Tolerance Behavior

`tolerance-ms` is checked lazily when the table is touched:

- when a new connection is admitted
- before an upstream payload is forwarded
- before a downstream payload is forwarded
- when a line releases its row

There is no background timer. A quiet line may sit idle longer than `tolerance-ms`; if another connection or payload
touches the same identity and removes that quiet line's IP row, the quiet line is closed the next time it tries to send
or receive payload.

Use a larger tolerance if clients commonly keep long idle connections open. Use a smaller tolerance if you want stale
IP slots to be freed quickly.

## Source IP Requirement

`SoftIpLimiter` requires a valid source IP in the Waterwall line source context. Normal stream listener nodes such as
`TcpListener` provide this.

If the source context is missing or is not an IPv4 or IPv6 address, the connection is rejected. This is intentional:
without a source IP, the node cannot enforce an IP limit.

## Logging

The node is silent by default.

When `verbose` is `true`, rejected admissions and active payload closures are logged with:

- identifier mode
- internal 64-bit identifier
- source IP
- worker id
- reason
- current IP count
- configured limit

Raw VLESS UUIDs and raw Trojan SHA224 values are not logged.

## Operational Notes

- `SoftIpLimiter` is not an authentication node. It only gates early traffic before the real protocol server parses it.
- Malformed or unidentified early data is rejected, not sent to fallback.
- The node does not know usernames. It keys only by the early VLESS UUID or Trojan SHA224 value.
- If `simultaneous-user-limit` is `1`, one identity may still open multiple simultaneous lines from the same source IP.
- If clients roam between networks, set `simultaneous-user-limit` high enough to cover the expected overlap.
- The maximum limit is intentionally small, so the per-identity table uses fixed-size storage.
- The table is in tunnel state, so it is shared by all workers of this tunnel instance and protected by an RW lock.

## Node Metadata

| Property | Value |
| --- | --- |
| Node flag | `kNodeFlagNone` |
| Previous node | Required |
| Next node | Required |
| Layer group | `kNodeLayer4` |
| Previous node layer | `kNodeLayer4` |
| Next node layer | `kNodeLayer4` |
| `required_padding_left` | `0` |

## Common Mistakes

- Placing `SoftIpLimiter(identifier=trojan)` before `TlsServer`. Trojan bytes are still encrypted there, so the limiter
  cannot identify the connection.
- Placing `SoftIpLimiter` after `VlessServer` or `TrojanServer`. The limiter is designed to see the raw protocol identity
  before the parser consumes it.
- Expecting it to authenticate the user. The following `VlessServer` or `TrojanServer` still authenticates.
- Setting `simultaneous-user-limit` higher than `6`.
- Using it in packet chains. It is a stream-only node.
