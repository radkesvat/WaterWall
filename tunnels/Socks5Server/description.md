<!--
Documentation version: 158
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/Socks5Server.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/Socks5Server.mdx, and all files must keep the same documentation version.
-->

# Socks5Server Node

`Socks5Server` is a server-side SOCKS5 middle tunnel for Waterwall.

It accepts SOCKS5 control traffic from its previous node, performs username/password authentication through an existing
`AuthenticationClient` node, then either:

- opens a normal Waterwall upstream connection for `CONNECT`, or
- creates an authenticated UDP association with a dynamic bound UDP endpoint for `UDP ASSOCIATE`

This tunnel is written to fit normal Waterwall chain rules:

- TCP-only service normally starts at `TcpListener`; service with UDP support normally starts at `TcpUdpListener`
- the next node still performs the real outbound transport work
- line state is created during `Init`
- finishes destroy local state before propagating the real Waterwall close
- in authenticated mode, `Socks5Server` creates and inserts its own internal `UserController` between itself and the
  configured next node

## What It Does

- Implements SOCKS5 method negotiation.
- Supports username/password authentication through `AuthenticationClient`.
- Supports `CONNECT`.
- Supports `UDP ASSOCIATE` with dynamic endpoint allocation via `UdpListener` / `TcpUdpListener`.
- Rejects `BIND`.
- Holds TCP payload until the SOCKS5 `CONNECT` request is accepted.
- Authenticates UDP datagrams against a live TCP control connection.
- Creates internal backend UDP lines per requested remote destination.
- Wraps returned UDP payload back into SOCKS5 UDP datagrams.

## Typical Placement

TCP-only SOCKS5 server:

- `TcpListener -> Socks5Server -> TcpConnector`

SOCKS5 server with combined `CONNECT` and UDP support:

- `TcpUdpListener -> [optional middle tunnels] -> Socks5Server -> TcpUdpConnector`

There is one previous callback path, not separate TCP and UDP chains into one
`Socks5Server`. `TcpUdpListener` supplies both TCP control ingress and the
private dynamic UDP provider on that one path. `udp: true` fails startup if the
finalized preceding path has no `UdpListener`/`TcpUdpListener` provider.

> **Required topology for SOCKS5 UDP:** Use `TcpUdpListener` for the normal built-in deployment. `TcpListener` alone can
> carry the SOCKS5 TCP control connection and `CONNECT`, but it cannot provide the dynamic UDP endpoint required by
> `UDP ASSOCIATE`. A bare `UdpListener` exposes the provider capability, but by itself cannot accept the required TCP
> control connection. It is useful only inside a custom fan-in topology that supplies TCP on the same callback path.
> `Socks5Server` discovers the provider automatically from its finalized preceding path; there is no provider-name or
> provider-API JSON setting.

Important:

- Do not manually place a `UserController` directly after an authenticated `Socks5Server`; it is inserted internally.
- `CONNECT` uses the TCP control line and forwards upstream through the normal next tunnel.
- `UDP ASSOCIATE` does not create a downstream TCP stream.
- UDP payload is only accepted when the sender matches an authenticated live TCP control association.

## Complete SOCKS5 TCP/UDP Topology Example

```json
{
  "name": "socks5-service",
  "nodes": [
    {
      "name": "socks-entry",
      "type": "TcpUdpListener",
      "settings": {
        "address": "0.0.0.0",
        "port": 1080,
        "nodelay": true
      },
      "next": "socks-server"
    },
    {
      "name": "socks-server",
      "type": "Socks5Server",
      "settings": {
        "no-auth": true,
        "connect": true,
        "udp": true,
        "ipv4": "203.0.113.10"
      },
      "next": "outbound"
    },
    {
      "name": "outbound",
      "type": "TcpUdpConnector",
      "settings": {
        "address": "dest_context->address",
        "port": "dest_context->port",
        "nodelay": true,
        "fastopen": false
      }
    }
  ]
}
```

Replace `203.0.113.10` with an IPv4 address that the SOCKS5 clients can actually reach. The example uses `no-auth` only
to keep the topology visible; an Internet-facing deployment should normally use `auth-client-node-name` and a configured
`AuthenticationClient`.

The addresses and ports in this topology have different jobs:

| Setting or value | Meaning |
| --- | --- |
| `TcpUdpListener.settings.address` | Local address on which the TCP listener and dynamically created UDP sockets bind. |
| `TcpUdpListener.settings.port` | Public SOCKS5 TCP control port. The internal static UDP child also listens here, but `Socks5Server` does not accept that fixed port as a SOCKS UDP association. |
| `Socks5Server.settings.ipv4` | IPv4 address advertised to the SOCKS5 client in `BND.ADDR`; it must be reachable by that client. It is not the socket bind setting. |
| Reply `BND.PORT` | Per-association UDP relay port chosen dynamically by the operating system and returned by `UDP ASSOCIATE`. |

For authenticated mode, replace `no-auth` with `auth-client-node-name`. That name must refer to a configured
`AuthenticationClient` in the same file. `Socks5Server` uses that existing node and inserts its own internal
`UserController` before `outbound`.

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
- when `udp` is enabled, the finalized preceding path must expose a dynamic UDP provider; normally this means starting
  the service with `TcpUdpListener`

## Optional `settings` Fields

- `connect` `(boolean)`
  Enables SOCKS5 `CONNECT`.
  Default: `true`

- `udp` `(boolean)`
  Enables SOCKS5 `UDP ASSOCIATE`.
  Default: `false`

- `ipv4` `(string)`
  Required when `udp` is enabled.

  This is the reachable IPv4 address placed in the SOCKS5 UDP associate reply as `BND.ADDR`; it is not the listener bind
  address.
  The reply port is dynamically allocated: `Socks5Server` requests a dynamic, dedicated bound UDP endpoint from the preceding `UdpListener` (or `TcpUdpListener`), and returns the assigned ephemeral port to the client.

- `verbose` `(boolean)`
  Enables extra debug logging.

- `sweep-interval-ms` `(integer)`
  Optional setting forwarded to the internal `UserController` in authenticated mode.
  Default: `1000`

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

The resulting `user_handle_t` is stored in `Socks5Server` line state and copied into `line_t` through `lineAddUser()`.
The raw SOCKS username/password are also stored as a line credential marker for downstream `Router` username/password
rules. In no-auth mode the handle stays empty and `lineAddUser()` stores an empty anonymous handle marker. Multiple
protocol/authentication servers can add separate auth markers to one line without sharing one mutable global user slot.
The internal `UserController` reads this handle on upstream `Init` and enforces the user's live connection, IP, traffic,
expiry, and enabled-state limits before the line reaches the configured next tunnel.

For `CONNECT`:

- the requested destination is copied into `line->routing_context.dest_ctx`
- the transport protocol is set to TCP
- upstream `Init` is sent to the next tunnel
- payload is buffered until downstream `Est` arrives
- only then does the tunnel send the SOCKS5 success reply and emit downstream `Est` toward the previous node

For `UDP ASSOCIATE`:

- no upstream transport line is created from the control line
- the provider is discovered automatically from the finalized preceding callback path
- a dynamic bound UDP endpoint is opened via the upstream `UdpListener` (or `TcpUdpListener`)
- a UDP association is registered in the worker-local registry
- the reply address uses `settings.ipv4`
- the reply port uses the assigned dynamic ephemeral port

At UDP `Init` and again before the first UDP payload, the endpoint metadata must
name the line's actual owner WID and active association handle. A valid-current-
worker metadata/WID mismatch is an ordinary fail-closed UDP-only rejection: it
creates no remote line, sends no reply, and never closes or messages the TCP
control line. A callback invoked from a different current worker is instead a
fatal core invariant; it is rejected before line state or worker-local resources
are accessed.

If the dedicated bind, endpoint activation, or reply allocation fails, only that association fails with a SOCKS5
general-failure reply; existing associations remain intact. The returned endpoint must be reachable through any firewall
or NAT policy. Static/fixed-port UDP listener traffic is not accepted as a SOCKS association.

### UDP association security model

This tunnel does not allow the UDP port to behave like an open proxy.

Current checks:

- the datagram arrives on the dynamic bound UDP socket assigned to that client association
- the datagram source matches the pinned or expected peer address
- the association was created by an accepted TCP control line on the current worker
- the association registry entry must still be present

A concrete UDP-associate peer IP that differs from the TCP control peer is rejected. A wildcard peer IP uses the control
peer IP; a zero UDP source port is pinned by the first matching datagram. Standard SOCKS5 does not cryptographically
authenticate individual UDP datagrams. Consequently, a peer sharing the expected public IP that learns a dedicated relay
port can race the first packet when the requested source port is zero; stronger per-datagram authentication needs a
separately designed encapsulation or token protocol.

When the TCP control line closes:

- the dynamic UDP endpoint is closed in `UdpListener`
- the UDP association is removed immediately from the worker-local map
- later UDP packets from that sender are rejected

Associations are stored in a worker-local hash map on `socks5server_tstate_t` without cross-worker lock contention.

Registry entries store copied metadata only:

- a generation token
- the owner worker id for diagnostics
- the dynamic endpoint handle
- the authenticated `user_handle_t`, or an empty handle in no-auth mode
- copied raw username/password strings, when authenticated mode is used

They do not store a usable `line_t *`, and UDP lookup never calls `lineRef()` or `lineUnref()` on
the TCP control line. The complete dynamic endpoint handle (owner WID plus
generation) is the association identity; there is no network-tuple association
key. A closing control line removes only the entry whose complete handle still
matches.

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

- control-line teardown marks the line closing before final SOCKS5 bytes, closes the dynamic endpoint, and destroys local state
  before propagating real `Finish` callbacks
- UDP associations are unregistered before the control line is allowed to die
- internal UDP remote lines detach from their client line before being finished
- re-entrant callbacks are protected so the tunnel does not read line state after shutdown paths

## Notes And Caveats

- `BIND` is currently rejected with `command not supported`.
- SOCKS5 UDP fragmentation is not reassembled; packets with `FRAG != 0` are ignored.
- `TcpListener -> Socks5Server` is a TCP-only topology. Use `TcpUdpListener` when `udp: true`; do not send SOCKS UDP
  datagrams to the configured static listener port.
- SOCKS5 usernames and passwords are converted into one AuthenticationClient password lookup key with a literal `:`
  separator. Embedded NUL bytes are rejected because AuthenticationClient password lookup uses C strings.
- Dynamic UDP relay ports require a reachable firewall/NAT path; permitting only the TCP control port is insufficient.
- `required_padding_left` is set for the worst-case SOCKS5 UDP header so the tunnel can prepend UDP headers without
  breaking Waterwall buffer-padding assumptions.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagNone` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `262` bytes |
