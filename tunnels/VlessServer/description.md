# VlessServer Node

`VlessServer` is a server-side VLESS v0 protocol middle tunnel for Waterwall.

It accepts a base VLESS byte stream from the previous node, authenticates the 16-byte raw UUID in the request header
against a configured UUID allowlist, parses the requested TCP or UDP destination, and forwards accepted traffic to the
configured `next` node.

This node implements plain VLESS protocol handling only. It does not create TLS, REALITY, XTLS Vision, mux, reverse, or
transport-specific wrapping.

## What It Does

- Parses VLESS v0 request headers.
- Authenticates users by UUID allowlist.
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
- This node uses a local UUID allowlist; it does not currently use `AuthenticationClient` or `UserController`.

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

Multiple users:

```json
{
  "name": "vless-server",
  "type": "VlessServer",
  "settings": {
    "users": [
      "5783a3e7-e373-51cd-8642-c83782b807c5",
      {
        "id": "11111111-2222-3333-4444-555555555555"
      }
    ],
    "connect": true,
    "udp": true
  },
  "next": "outbound"
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

At least one UUID must be configured using one or more of:

- `uuid` `(string)`
  A single RFC4122 UUID string.

- `id` `(string)`
  Alias for `uuid`.

- `uuids` `(array of strings)`
  Multiple UUID strings.

- `users` `(array)`
  Each entry may be a UUID string or an object containing `uuid`, `id`, or `user-id`.

- `clients` `(array)`
  Alias for `users`.

UUID strings may be dashed RFC4122 form or compact 32-character hex form. The wire comparison uses RFC4122 byte order:
hex bytes left-to-right, not Windows GUID memory order.

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

## Unsupported Features

The current implementation intentionally rejects:

- nonzero addons length
- XTLS Vision flow addons
- mux command `0x03`
- reverse command `0x04`
- unknown commands
- fallback routing
- VLESS over non-stream transports
- XUDP and advanced UDP/mux behavior

Invalid authentication and malformed protocol data are handled by closing the line without writing a VLESS response
header.
