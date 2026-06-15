# Socks5Server Node

`Socks5Server` is a server-side SOCKS5 middle tunnel for Waterwall.

It accepts SOCKS5 control traffic from its previous node, performs username/password authentication through an existing
`AuthenticationClient` node, then either:

- opens a normal Waterwall upstream connection for `CONNECT`, or
- creates an authenticated UDP association for `UDP ASSOCIATE`

This tunnel is written to fit normal Waterwall chain rules:

- the previous node is usually a listener such as `TcpListener` or `UdpListener`
- the next node still performs the real outbound transport work
- line state is created during `Init`
- finishes destroy local state before propagating the real Waterwall close

## What It Does

- Implements SOCKS5 method negotiation.
- Supports username/password authentication through `AuthenticationClient`.
- Supports `CONNECT`.
- Supports `UDP ASSOCIATE`.
- Rejects `BIND`.
- Holds TCP payload until the SOCKS5 `CONNECT` request is accepted.
- Authenticates UDP datagrams against a live TCP control connection.
- Creates internal backend UDP lines per requested remote destination.
- Wraps returned UDP payload back into SOCKS5 UDP datagrams.

## Typical Placement

TCP-only SOCKS5 server:

- `TcpListener -> Socks5Server -> TcpConnector`

SOCKS5 server with UDP support:

- `TcpListener -> Socks5Server -> TcpConnector`
- `UdpListener -> Socks5Server -> UdpConnector`

The same `Socks5Server` implementation handles both paths.

Important:

- `CONNECT` uses the TCP control line and forwards upstream through the normal next tunnel.
- `UDP ASSOCIATE` does not create a downstream TCP stream.
- UDP payload is only accepted when the sender matches an authenticated live TCP control association.

## Configuration Example

```json
{
  "name": "socks-server",
  "type": "Socks5Server",
  "settings": {
    "auth-client-node-name": "auth-client",
    "connect": true,
    "udp": true,
    "ipv4": "0.0.0.0",
    "verbose": false
  },
  "next": "next-node-name"
}
```

`auth-client` must be a configured `AuthenticationClient` node in the same config file. `Socks5Server` only finds and
uses that node instance; it does not create an authentication client.

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"Socks5Server"`.

### `settings`

- `auth-client-node-name` `(string)`
  Name of an existing `AuthenticationClient` node in the same config file. Required unless `no-auth` is explicitly `true`.

- `no-auth` `(boolean)`
  Enables SOCKS5 no-authentication mode when `auth-client-node-name` is not set.
  Default: `false`

However:

- exactly one authentication mode must be selected: either `auth-client-node-name` or `no-auth: true`
- at least one of `connect` or `udp` must be enabled
- when `udp` is enabled, `ipv4` is required

## Optional `settings` Fields

- `connect` `(boolean)`
  Enables SOCKS5 `CONNECT`.
  Default: `true`

- `udp` `(boolean)`
  Enables SOCKS5 `UDP ASSOCIATE`.
  Default: `false`

- `ipv4` `(string)`
  Required when `udp` is enabled.

  This is the IPv4 address placed in the SOCKS5 UDP associate reply.
  The reply port is not configured here. It is taken from the current TCP listener port that accepted the control
  connection.

  Example:

  - if the TCP control connection came in through local port `443`
  - and `ipv4` is `"0.0.0.0"`

  then the UDP associate reply is effectively:

  - `0.0.0.0:443`

- `verbose` `(boolean)`
  Enables extra debug logging.

## Detailed Behavior

### Control-line behavior

When a TCP line reaches `Socks5Server`:

- line state is initialized as a TCP control line
- the tunnel waits for the SOCKS5 greeting
- when `auth-client-node-name` is configured, it requires SOCKS5 username/password authentication
- in username/password mode, it builds one authentication lookup key as `username:password`
- in username/password mode, it checks that combined string through the configured `AuthenticationClient` as the user's password
- when `no-auth` is explicitly `true`, it selects SOCKS5 no-authentication if the client offered it
- after successful authentication or accepted no-auth negotiation, it waits for the SOCKS5 request

The old local `username`, `password`, `users`, and `accounts` settings are no longer accepted.

In username/password mode, AuthenticationServer users for this tunnel should store the SOCKS credential pair in the user
object's `password` field using that exact `username:password` form. The user object's `name` is not used for
Socks5Server authentication and may be kept as operator metadata.

The resulting `user_handle_t` is stored only in `Socks5Server` line state. In no-auth mode this handle stays empty. It is
not written into `line_t` or `routing_context_t`, so multiple protocol/authentication servers can coexist in one chain
without sharing one global user slot.

For `CONNECT`:

- the requested destination is copied into `line->routing_context.dest_ctx`
- the transport protocol is set to TCP
- upstream `Init` is sent to the next tunnel
- payload is buffered until downstream `Est` arrives
- only then does the tunnel send the SOCKS5 success reply and emit downstream `Est` toward the previous node

For `UDP ASSOCIATE`:

- no upstream transport line is created from the control line
- a UDP association is registered against the authenticated TCP control line
- the reply address uses `settings.ipv4`
- the reply port uses the local TCP listener port that accepted this control connection

### UDP association security model

This tunnel does not allow the UDP port to behave like an open proxy.

Current checks:

- the sender must match a registered UDP association
- that association was created by an accepted TCP control line
- the association registry entry must still be present

When the TCP control line closes:

- the UDP association is removed immediately
- later UDP packets from that sender are rejected

Associations are stored in a sharded registry in `socks5server_tstate_t`. The registry is shared by
all workers for that Socks5Server tunnel instance. Each shard has its own mutex and map, so UDP
datagrams can be accepted on any worker without touching the TCP control line from that worker.

Registry entries store copied metadata only:

- a generation token
- the owner worker id for diagnostics
- the authenticated `user_handle_t`, or an empty handle in no-auth mode

They do not store a usable `line_t *`, and UDP lookup never calls `lineLock()` or `lineUnlock()` on
the TCP control line. The generation token prevents an older closing control line from deleting a
newer association that reused the same association key.

### UDP payload behavior

When an authenticated UDP datagram arrives:

- the tunnel validates the SOCKS5 UDP header
- fragmented SOCKS5 UDP packets (`FRAG != 0`) are ignored conservatively
- the requested destination is parsed from the UDP header
- a worker-local internal backend UDP line is created or reused for that destination
- the UDP payload body is sent upstream through that internal line

When a reply comes back from the next tunnel:

- the reply payload is wrapped into a SOCKS5 UDP response header
- the source address in that header is the remote destination represented by the backend UDP line
- the wrapped datagram is sent back toward the previous node

### Internal backend UDP lines

For UDP forwarding, `Socks5Server` creates normal Waterwall lines behind the UDP client side.

This is important for composability:

- the UDP listener line remains the client-facing association line
- per-remote outbound destinations get their own backend lines
- the packet line model is not abused as if it were a normal closable connection line

### Finish behavior

The implementation follows normal Waterwall finish ordering:

- control-line teardown marks the line closing before final SOCKS5 bytes, then destroys local state
  before propagating real `Finish` callbacks
- UDP associations are unregistered before the control line is allowed to die
- internal UDP remote lines detach from their client line before being finished
- re-entrant callbacks are protected so the tunnel does not read line state after shutdown paths

## Notes And Caveats

- `BIND` is currently rejected with `command not supported`.
- SOCKS5 UDP fragmentation is not reassembled; packets with `FRAG != 0` are ignored.
- UDP support currently assumes your TCP and UDP listener topology is arranged so the returned TCP listener port is the
  correct SOCKS5 UDP port for the client to use.
- SOCKS5 usernames and passwords are converted into one AuthenticationClient password lookup key with a literal `:`
  separator. Embedded NUL bytes are rejected because AuthenticationClient password lookup uses C strings.
- `required_padding_left` is set for the worst-case SOCKS5 UDP header so the tunnel can prepend UDP headers without
  breaking Waterwall buffer-padding assumptions.
