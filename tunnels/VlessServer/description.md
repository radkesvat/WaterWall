# VlessServer Node

`VlessServer` is a server-side VLESS v0 protocol middle tunnel for Waterwall.

It accepts a base VLESS byte stream from the previous node, authenticates the 16-byte raw UUID in the request header,
parses the requested TCP or UDP destination, and forwards accepted traffic to the configured `next` node.

Authentication can run in either local allowlist mode or user-database mode:

- Without `auth-client-node-name`, `VlessServer` uses the configured local UUID allowlist.
- With `auth-client-node-name`, `VlessServer` authenticates through `AuthenticationClient`, records the resulting
  `user_handle_t` on the line, and internally inserts a `UserController` before the configured outbound node.

This node implements plain VLESS protocol handling only. It does not create TLS, REALITY, XTLS Vision, mux, reverse, or
transport-specific wrapping.

## What It Does

- Parses VLESS v0 request headers.
- Authenticates users by local UUID allowlist or by `AuthenticationClient`.
- Optionally forwards unauthenticated invalid probes to a fallback branch.
- Supports VLESS TCP command `0x01`.
- Supports VLESS UDP command `0x02`.
- Rejects non-empty addons, including Vision flow addons.
- Rejects mux, reverse, unknown commands, malformed destinations, empty domain names, and zero ports.
- Sends the base VLESS response header `00 00` after the selected upstream side is established.
- Preserves any TCP body bytes that arrive in the same payload as the request header.
- Uses VLESS UDP length framing: `uint16_be length` followed by one UDP payload.
- Creates one internal backend UDP line for the UDP destination carried by the initial VLESS request.

## Typical Placement

Normal VLESS server:

```text
TcpListener -> TlsServer -> VlessServer -> TcpUdpConnector
```

TCP-only outbound:

```text
TcpListener -> TlsServer -> VlessServer -> TcpConnector
```

Important:

- `VlessServer` does not create or manage TLS.
- Operators should place `TlsServer` before `VlessServer` for normal VLESS deployments.
- Without TLS, the UUID and destination metadata are visible on the wire.
- The UUID is a bearer credential. Anyone who knows it can authenticate.
- In user-database mode, put the canonical lowercase dashed UUID string in the user's `password` field.

## Configuration Example

Minimal server with one UUID:

```json
{
  "name": "vless-server",
  "type": "VlessServer",
  "settings": {
    "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "connect": true,
    "udp": true,
    "verbose": false
  },
  "next": "outbound"
}
```

Multiple local allowlist users:

```json
{
  "name": "vless-server",
  "type": "VlessServer",
  "settings": {
    "users": [
      "5783a3e7-e373-51cd-8642-c83782b807c5",
      {
        "username": "alice",
        "id": "11111111-2222-3333-4444-555555555555"
      }
    ],
    "connect": true,
    "udp": true
  },
  "next": "outbound"
}
```

Database-backed authentication:

```json
{
  "name": "vless-server",
  "type": "VlessServer",
  "settings": {
    "auth-client-node-name": "auth-client",
    "connect": true,
    "udp": true
  },
  "next": "outbound"
}
```

Example with fallback:

```json
{
  "name": "vless-server",
  "type": "VlessServer",
  "settings": {
    "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "fallback-node-name": "fallback-service",
    "connect": true,
    "udp": true
  },
  "next": "outbound"
}
```

The matching user database entry should use the canonical UUID string as the password:

```json
{
  "id": 2001,
  "name": "vless-user",
  "password": "5783a3e7-e373-51cd-8642-c83782b807c5",
  "enabled": true
}
```

Typical outbound connector:

```json
{
  "name": "outbound",
  "type": "TcpUdpConnector",
  "settings": {
    "address": "dest_context->address",
    "port": "dest_context->port"
  }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"VlessServer"`.

- `next` `(string)`
  Required. Accepted VLESS traffic is forwarded to this node.

### `settings`

Choose exactly one authentication mode.

For local allowlist mode, omit `auth-client-node-name` and configure at least one UUID using one or more of:

- `uuid` `(string)`
  A single RFC4122 UUID string.

- `id` `(string)`
  Alias for `uuid`. Use either `uuid` or `id`, not both.

- `uuids` `(array of strings)`
  Multiple UUID strings.

- `users` `(array)`
  Each entry may be a UUID string or an object containing exactly one of `uuid`, `id`, or `user-id`. Object entries may
  also include an optional `username` string, which is recorded on the line if that UUID authenticates.

- `clients` `(array)`
  Alias for `users`. Use either `users` or `clients`, not both.

Duplicate local UUIDs are a fatal configuration error, regardless of whether the duplicate entries use different
`username` values.

UUID strings may be dashed RFC4122 form or compact 32-character hex form. The wire comparison uses RFC4122 byte order:
hex bytes left-to-right, not Windows GUID memory order.

For user-database mode, configure:

- `auth-client-node-name` `(string)`
  Name of an existing `AuthenticationClient` node in the same config file.

In this mode, local UUID settings (`uuid`, `id`, `uuids`, `users`, `clients`) are rejected so the user database remains
the only authority. The wire UUID is converted to canonical lowercase dashed form before lookup, for example:

```text
5783a3e7-e373-51cd-8642-c83782b807c5
```

That string is authenticated as the user's `password` through `AuthenticationClient`.

In local allowlist mode, the canonical lowercase dashed UUID string is stored as the line's raw password after the full
VLESS request is parsed, so `Router` can match `password` rules without a users database. If the matching local object
has `username`, that username is also stored on the line for `Router` username rules.

The complete VLESS credential, meaning the version byte plus the 16-byte raw UUID, must be present in the first upstream
payload callback. If the first payload does not contain the full UUID, `VlessServer` sends the unauthenticated bytes to
fallback when fallback is configured; otherwise it rejects the line. This path logs a warning even when `verbose` is
disabled. Fields after the UUID, including addons length, command, destination, and any early payload, may still arrive
buffered across later payload callbacks.

At least one of `connect` or `udp` must be enabled.

## Optional `settings` Fields

- `connect` `(boolean)`
  Enables VLESS TCP command `0x01`.
  Default: `true`

- `udp` `(boolean)`
  Enables VLESS UDP command `0x02`.
  Default: `true`

- `verbose` `(boolean)`
  Enables extra rejection logging.
  Default: `false`

- `fallback-node-name` `(string)`
  Name of an existing node used as fallback for unauthenticated invalid probes or failed authentication.

  Accepted aliases:

  - `fallback-node`
  - `fallback`

## Protocol Behavior

Accepted request format:

```text
version:      1 byte, must be 00
user id:      16 raw UUID bytes
addons len:   1 byte, must be 00
command:      01 TCP or 02 UDP
destination:  port first, then address
body:         TCP raw stream or UDP length-prefixed packets
```

Destination format:

```text
port:         2 bytes big-endian
address type: 01 IPv4, 02 domain, 03 IPv6
address body: IPv4 4 bytes, domain length + bytes, or IPv6 16 bytes
```

Response format:

```text
00 00
```

The response header is sent only after the selected upstream path establishes. For TCP this means the outbound
connection has established. For UDP this means the backend UDP line has initialized through the next node.

UDP packets after the request header use:

```text
length:  2 bytes big-endian
payload: length bytes
```

The UDP destination is fixed by the initial VLESS request. Individual UDP frames do not carry per-packet addresses.

## Fallback Behavior

Fallback is intended for active-probing resistance.

When fallback is configured, unauthenticated traffic that does not look like a valid VLESS request is forwarded to the
fallback branch with the original buffered bytes preserved. `VlessServer` does not send a VLESS response header before
doing this.

Fallback may be selected for:

- invalid version byte
- segmented UUID authentication in the first upstream payload
- failed UUID lookup
- authentication client not ready

Fallback is not used after the UUID has authenticated. Once the UUID is accepted, malformed VLESS addons, command,
destination, or UDP framing closes the VLESS line instead of replaying authenticated client bytes to the fallback
service.

Operational notes:

- The fallback target must be a real configured node.
- It must not be `VlessServer` itself.
- It must not be the internal `UserController`.
- It should be something that plausibly speaks the public-facing protocol exposed by the same endpoint.
- If no fallback is configured, unauthenticated invalid probes are closed.

## Unsupported Features

The current implementation intentionally rejects:

- nonzero addons length
- XTLS Vision flow addons
- mux command `0x03`
- reverse command `0x04`
- unknown commands
- VLESS over non-stream transports
- XUDP and advanced UDP/mux behavior

Invalid unauthenticated probes may go to fallback; bad authenticated protocol data closes without writing another VLESS
response header.
