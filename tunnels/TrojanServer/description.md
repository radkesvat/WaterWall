# TrojanServer Node

`TrojanServer` is a server-side Trojan protocol middle tunnel for Waterwall.

It accepts a Trojan byte stream from the previous node, authenticates the standard Trojan SHA-224 password, parses the
requested TCP or UDP destination, and forwards accepted traffic to the configured `next` node.

Authentication can run in either local allowlist mode or user-database mode:

- Without `auth-client-node-name`, `TrojanServer` uses configured local raw passwords. This is useful when you only need
  basic password authentication and do not need user tracking or limits.
- With `auth-client-node-name`, `TrojanServer` authenticates through `AuthenticationClient`, records the resulting
  `user_handle_t` on the line, and internally inserts a `UserController` before the configured outbound `next` node.

This node replaces the old two-node Trojan server setup for database-backed deployments. Users no longer need to place
separate `TrojanAuthServer` and `TrojanSocksServer` nodes in the chain.

## What It Does

- Parses the Trojan request header.
- Authenticates Trojan passwords by local raw-password allowlist or by `AuthenticationClient`.
- Creates an internal `UserController` for authenticated user enforcement in database mode.
- Supports Trojan TCP `CONNECT`.
- Supports Trojan UDP `ASSOCIATE` over the Trojan TCP stream.
- Creates internal backend UDP lines per requested UDP destination.
- Wraps UDP replies back into Trojan UDP packet framing.
- Optionally forwards unauthenticated invalid probes to a fallback branch.

## Typical Placement

Normal Trojan server:

```text
TcpListener -> TlsServer -> TrojanServer -> TcpUdpConnector
```

TCP-only outbound:

```text
TcpListener -> TlsServer -> TrojanServer -> TcpConnector
```

Important:

- `TrojanServer` does not create or manage TLS.
- Operators must place `TlsServer` before `TrojanServer` for a normal Trojan deployment.
- Without TLS, Trojan password hashes and request metadata are exposed on the wire.
- Do not manually place a `UserController` directly after `TrojanServer` in database mode; that mode creates one
  internally.
- In user-database mode, `auth-client-node-name` must point to an existing `AuthenticationClient` node in the same
  configuration.

## Configuration Example

Minimal local-password `TrojanServer` node:

```json
{
  "name": "trojan-server",
  "type": "TrojanServer",
  "settings": {
    "password": "secret-password",
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
  "name": "trojan-server",
  "type": "TrojanServer",
  "settings": {
    "users": [
      "secret-password",
      {
        "username": "alice",
        "password": "another-secret"
      }
    ],
    "connect": true,
    "udp": true
  },
  "next": "outbound"
}
```

Database-backed `TrojanServer` node:

```json
{
  "name": "trojan-server",
  "type": "TrojanServer",
  "settings": {
    "auth-client-node-name": "auth-client",
    "connect": true,
    "udp": true,
    "verbose": false
  },
  "next": "outbound"
}
```

Example with fallback:

```json
{
  "name": "trojan-server",
  "type": "TrojanServer",
  "settings": {
    "auth-client-node-name": "auth-client",
    "fallback-node-name": "fallback-service",
    "connect": true,
    "udp": true,
    "sweep-interval-ms": 1000,
    "verbose": false
  },
  "next": "outbound"
}
```

Example chain sketch:

```json
{
  "name": "listener",
  "type": "TcpListener",
  "settings": {
    "address": "0.0.0.0",
    "port": 443
  },
  "next": "tls-server"
}
```

```json
{
  "name": "tls-server",
  "type": "TlsServer",
  "settings": {
    "cert-file": "server.crt",
    "key-file": "server.key"
  },
  "next": "trojan-server"
}
```

```json
{
  "name": "trojan-server",
  "type": "TrojanServer",
  "settings": {
    "auth-client-node-name": "auth-client",
    "fallback-node-name": "fallback-service",
    "connect": true,
    "udp": true
  },
  "next": "outbound"
}
```

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

The exact listener, TLS, connector, and fallback node settings depend on those node types. The important part is that
`TrojanServer` sits after TLS termination and before the outbound connector.

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TrojanServer"`.

- `next` `(string)`
  Required. This is the outbound branch used after successful Trojan authentication and protocol parsing.

### `settings`

Choose exactly one authentication mode.

For local allowlist mode, omit `auth-client-node-name` and configure at least one raw password using one or more of:

- `password` `(string)`
  A single raw Trojan password.

- `pass` `(string)`
  Alias for `password`. Use either `password` or `pass`, not both.

- `passwords` `(array of strings)`
  Multiple raw Trojan passwords.

- `users` `(array)`
  Each entry may be a raw password string or an object containing `password` or `pass`, but not both. Object entries may
  also include an optional `username` string, which is recorded on the line if that password authenticates.

- `clients` `(array)`
  Alias for `users`. Use either `users` or `clients`, not both.

Duplicate local passwords are a fatal configuration error, regardless of whether the duplicate entries use different
`username` values.

For user-database mode, configure:

- `auth-client-node-name` `(string)`
  Name of an existing `AuthenticationClient` node in the same config file. It must point to `AuthenticationClient`, not
  to `TrojanServer` itself.

In this mode, local password settings (`password`, `pass`, `passwords`, `users`, `clients`) are rejected so the user
database remains the only authority.

At least one of `connect` or `udp` must be enabled.

## Optional `settings` Fields

- `fallback-node-name` `(string)`
  Name of an existing node used as fallback for unauthenticated invalid probes or failed authentication.

  Aliases:

  - `fallback-node`
  - `fallback`

- `connect` `(boolean)`
  Enables Trojan TCP `CONNECT`.
  Default: `true`

- `udp` `(boolean)`
  Enables Trojan UDP `ASSOCIATE` over the Trojan TCP stream.
  Default: `true`

- `verbose` `(boolean)`
  Enables focused authentication diagnostics.
  Default: `false`

- `sweep-interval-ms` `(integer)`
  Optional setting forwarded to the internally created `UserController`.
  Default: `1000`

## Authentication

Trojan clients send a 56-character hex string:

```text
hex(SHA224(password))
```

`TrojanServer` decodes that hash and authenticates it according to the selected mode.

In local allowlist mode, `TrojanServer` precomputes SHA-224 for each configured raw password and compares the decoded
wire hash against that allowlist. After the full Trojan request is parsed, it stores the matched raw password on the
`line_t` with no user marker, so `Router` can match `password` rules even though no `AuthenticationClient` user exists.
If the matching local object has `username`, that username is also stored on the line for `Router` username rules.

In user-database mode, `TrojanServer` asks the configured `AuthenticationClient` for the matching user through its
SHA-224 lookup API. For user database configuration:

- store the user's plaintext Trojan password in the user object's `password` field
- `AuthenticationClient` computes and stores the hash locally
- `TrojanServer` does not use the user object's `name` as the Trojan username

There is no unauthenticated mode for `TrojanServer`.

After successful database-backed authentication:

- the resulting `user_handle_t` is cached in this tunnel's line state
- the handle is added to the `line_t` with `lineAddUser()` after the full Trojan request is parsed
- the internal `UserController` enforces live user limits before the line reaches the configured outbound `next`

The complete 56-byte password hash must be present in the first upstream payload callback. If the first payload does not
contain the full hash, `TrojanServer` sends the unauthenticated bytes to fallback when fallback is configured; otherwise
it rejects the line. This path logs a warning even when `verbose` is disabled. Bytes after the password hash, including
the CRLF, command, address, and any early payload, may still arrive buffered across later payload callbacks. After the
password authenticates, the result is reused while those remaining request bytes arrive.

## Fallback Behavior

Fallback is intended for active-probing resistance.

When fallback is configured, unauthenticated traffic that does not look like a valid Trojan request is forwarded to the
fallback branch with the original buffered bytes preserved. `TrojanServer` does not send a Trojan-specific error before
doing this.

Fallback may be selected for:

- invalid password prefix bytes
- segmented password authentication in the first upstream payload
- invalid password CRLF before authentication
- invalid password hex before authentication
- failed password lookup
- authentication client not ready
- an incomplete unauthenticated prefix that grows beyond the maximum initial-buffer limit

Fallback is not used after the password has authenticated. Once the password is accepted, malformed Trojan command,
address, CRLF, or UDP framing closes the Trojan line instead of replaying authenticated client bytes to the fallback
service.

Operational notes:

- The fallback target must be a real configured node.
- It must not be `TrojanServer` itself.
- It must not be the internal `UserController`.
- It should be something that plausibly speaks the public-facing protocol exposed by the same TLS endpoint.
- If no fallback is configured, unauthenticated invalid probes are closed.

## TCP CONNECT Behavior

For Trojan TCP `CONNECT`:

- the requested destination is parsed from the Trojan request
- the destination is copied into `line->routing_context.dest_ctx`
- the transport protocol is set to TCP
- upstream `Init` is sent to the configured outbound path through the internal `UserController`
- any payload bytes received after the Trojan header are forwarded upstream

The previous/downstream side is established only when the outbound side reports establishment through the normal
Waterwall `Est` path.

## UDP ASSOCIATE Behavior

Trojan UDP uses the Trojan TCP stream as the carrier. After a valid UDP associate request:

- the associate request address is treated as associate metadata
- each Trojan UDP packet carries its own real remote destination
- `TrojanServer` parses every Trojan UDP packet header
- one internal backend UDP line is created or reused per remote destination
- the UDP payload body is sent upstream through that backend line

When a UDP reply comes back:

- the backend line's destination is used as the source address in the Trojan UDP response header
- the payload is wrapped as a Trojan UDP packet
- the wrapped bytes are sent back over the original Trojan stream

This is different from treating the whole UDP associate stream as one fixed destination. A single Trojan UDP associate
session may talk to multiple remote UDP endpoints.

## Internal Lines And Lifecycle

`TrojanServer` uses normal Waterwall line rules:

- the client-facing Trojan stream line is created by the previous adapter, usually `TcpListener`
- `TrojanServer` does not destroy that client line
- internal UDP backend lines are created by `TrojanServer`
- because `TrojanServer` creates those backend lines, it is responsible for finishing and destroying them
- local line state is destroyed before propagating real Waterwall finish callbacks
- pause/resume callbacks are not reflected toward a side that has already finished

The tunnel is not a packet tunnel and does not use packet-line semantics.

## Buffer And Padding Notes

`TrojanServer` advertises enough `required_padding_left` for the largest Trojan UDP response header:

```text
ATYP + DOMAIN_LEN + DOMAIN + PORT + LEN + CRLF
```

When enough left padding is available, UDP responses are wrapped by prepending into the existing buffer. If a buffer does
not have enough left capacity, the tunnel allocates a new buffer and recycles the old one.

## Notes And Caveats

- A production Trojan deployment should place `TlsServer` before `TrojanServer`.
- `TrojanServer` does not support HTTP/3, QUIC-based Trojan variants, or non-standard Trojan extensions.
- `CONNECT` and `UDP ASSOCIATE` can be independently disabled, but at least one must remain enabled.
- Bad unauthenticated probes may go to fallback; bad authenticated protocol data closes.
- `AuthenticationClient` must be ready for password lookup. If it is not ready and fallback is configured, the original
  unauthenticated bytes are sent to fallback. Those bytes may include the presented Trojan password hash, so choose the
  fallback service accordingly.
- `required_padding_left` is set for UDP wrapping; do not reduce it unless the Trojan UDP header calculation changes.
