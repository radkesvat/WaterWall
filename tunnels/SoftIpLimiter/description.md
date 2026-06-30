<!--
Documentation version: 109
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/SoftIpLimiter.mdx, and both files must keep the same documentation version.
-->

# SoftIpLimiter Node

`SoftIpLimiter` is a stream middle tunnel that limits how many source IP addresses may use the same early VLESS or
Trojan identity at the same time. It does not need a local Waterwall user database or a list of VLESS/Trojan users; it
keys the limit directly from the identity bytes already present in the user's TCP connection.

It is intended to sit immediately before the clear protocol parser, or before a raw TCP relay to the server that will run
that parser:

- before `VlessServer`, or before a TCP relay to an upstream VLESS server, when `identifier` is `vless`
- before `TrojanServer`, or before a TCP relay to an upstream Trojan server, when `identifier` is `trojan`

The node reads only the minimum early bytes needed to identify the connection. If the identity is recognized, it checks
the source IP against an in-memory table and then forwards the original buffered bytes unchanged. If the identity cannot
be recognized, the default behavior is to pass the connection through without IP limiting; strict deployments can change
that to close the connection. It does not authenticate users, parse destinations, add headers, remove headers, or rewrite
payload. `VlessServer` or `TrojanServer` must still run after it and perform the real protocol authentication.

## What It Does

- Extracts a 64-bit internal key from the early VLESS UUID or Trojan SHA224 identity.
- Tracks up to `6` source IP addresses per identity.
- Treats multiple live connections from the same source IP as one IP row.
- Keeps a reference count for live lines from the same identity and source IP.
- Updates each IP row's `last-seen-ms` on every upstream and downstream payload.
- Prunes stale IP rows before admission and before forwarding payload.
- Gracefully closes a line if its IP row was removed or expired before its next payload transfer.
- Passes unidentified/malformed early data through by default, or closes it when `on-identification-failure` is `close`.
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

Relay in front of an existing upstream VLESS/Trojan server:

```text
TcpListener -> TlsServer -> SoftIpLimiter(identifier=trojan) -> TcpConnector(upstream Trojan server)
```

Important:

- Place `SoftIpLimiter` after any encryption or transport wrapper that hides the VLESS/Trojan bytes.
- Place it before the protocol parser, or before a raw `TcpConnector` relay to an upstream protocol parser.
- Use `identifier: "vless"` only for VLESS TCP traffic.
- Use `identifier: "trojan"` only for Trojan TCP traffic.
- For public Trojan deployments, TLS must already be terminated before `SoftIpLimiter`, usually by `TlsServer`.
- This node is stream-only. Do not use it as a packet tunnel or as a packet-line policy node.

## Supported Traffic Shape

`SoftIpLimiter` must receive a plain TCP stream whose first application bytes are the VLESS or Trojan identity bytes:

- VLESS TCP is supported when the first clear byte is the VLESS version byte.
- Trojan TCP is supported when the first clear bytes are the Trojan SHA224 password hash.
- TLS-wrapped clients are supported only when Waterwall terminates TLS first, usually with `TlsServer`.
- A remote VLESS/Trojan server is fine: put `SoftIpLimiter` on the ingress server where user traffic passes, then relay
  the unchanged TCP stream with `TcpConnector`.

These client-side shapes are not supported by this node:

- WebSocket
- gRPC
- XHTTP
- HTTP header or `Host`-based wrappers where HTTP bytes appear before the VLESS/Trojan identity
- any UDP or packet-chain placement

In those cases the VLESS/Trojan identity is not at the beginning of the clear TCP stream, so this node cannot identify
the user. Do not place it before `TlsServer`; encrypted bytes cannot be inspected.

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
    "on-identification-failure": "passthrough",
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
      "tolerance-ms": 30000,
      "on-identification-failure": "passthrough"
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

Minimal relay example when another server will parse Trojan after Waterwall forwards the stream:

```json
{
  "name": "trojan-soft-ip-limit",
  "type": "SoftIpLimiter",
  "settings": {
    "identifier": "trojan",
    "simultaneous-user-limit": 1,
    "tolerance-ms": 3000,
    "verbose": false
  },
  "next": "tcp-connector"
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
      "on-identification-failure": "close",
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

- `on-identification-failure` `(string)`
  Controls what happens when the first upstream bytes are definitely not valid for the configured `identifier` mode.

  Accepted values:

  - `passthrough` (default): initialize the next node, replay the buffered bytes unchanged, and stop applying IP limits
    to this line.
  - `close`: reject the line and close both directions.

  Aliases accepted for `passthrough`: `pass`, `pass-through`.

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

## Identification Failure Behavior

`SoftIpLimiter` waits while the buffer is too short to decide. Once the bytes are definitely invalid for the configured
mode, `on-identification-failure` decides the next step.

With the default `passthrough` behavior, the node becomes transparent for that line:

- the limiter does not insert an identity row
- `simultaneous-user-limit` and `tolerance-ms` no longer apply to that line
- the complete buffered data is replayed unchanged to the next node
- future payload, `Est`, `Pause`, `Resume`, and `Finish` callbacks pass through normally

This is useful when the following `VlessServer` or `TrojanServer` has its own fallback behavior, or when the same chain is
intentionally shared with non-VLESS/Trojan probes. Use `close` when this node should be a strict gate and malformed early
data must not reach the next node.

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

Be careful with very large values. With `simultaneous-user-limit: 1`, if `tolerance-ms` is set to one hour and a user
moves from mobile data to Wi-Fi, the first IP may keep occupying the identity's only slot for up to one hour after it
stops sending data. During that window the second IP can be rejected, and the older quiet line may be closed when it next
tries to transfer payload after its row is pruned. For common mobile or roaming clients, a short tolerance such as
`3000` to `5000` ms is often a more practical starting point.

## Source IP Requirement

For recognized identities, `SoftIpLimiter` requires a valid source IP in the Waterwall line source context. Normal stream
listener nodes such as `TcpListener` provide this.

If the source context is missing or is not an IPv4 or IPv6 address, the connection is rejected. This is intentional:
without a source IP, the node cannot enforce an IP limit.

If identification fails and `on-identification-failure` is `passthrough`, no source-IP row is created and this source-IP
requirement is not used for that line.

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
- `SoftIpLimiter` can run before a local `VlessServer`/`TrojanServer` or before a `TcpConnector` that relays to an
  upstream VLESS/Trojan server.
- It does not need fail2ban or another external limiter; the identity/IP table is maintained inside Waterwall.
- Malformed or unidentified early data is passed through by default. Set `on-identification-failure` to `close` to reject
  it at this node.
- The node does not know usernames. It keys only by the early VLESS UUID or Trojan SHA224 value.
- If `simultaneous-user-limit` is `1`, one identity may still open multiple simultaneous lines from the same source IP.
- If clients roam between networks, set `simultaneous-user-limit` high enough to cover the expected overlap.
- The maximum limit is intentionally small, so the per-identity table uses fixed-size storage.
- The table is in tunnel state, so it is shared by all workers of this tunnel instance and protected by an RW lock.
- Enable `verbose` temporarily when you need to confirm whether a connection was rejected or actively closed because of
  the IP limit.

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
- Expecting WebSocket, gRPC, XHTTP, or HTTP `Host`/header-style client configs to work. The limiter only understands raw
  VLESS/Trojan identity bytes at the start of a clear TCP stream.
- Placing `SoftIpLimiter` after `VlessServer` or `TrojanServer`. The limiter is designed to see the raw protocol identity
  before the parser consumes it.
- Expecting it to authenticate the user. The following `VlessServer` or `TrojanServer` still authenticates.
- Expecting default pass-through lines to be limited. They are forwarded without identity rows; use
  `"on-identification-failure": "close"` for strict enforcement.
- Setting `simultaneous-user-limit` higher than `6`.
- Using it in packet chains. It is a stream-only node.
