<!--
Documentation version: 159
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/Socks5Server.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/Socks5Server.mdx, and all files must keep the same documentation version.
-->

# Socks5Server Node

`Socks5Server` is a server-side SOCKS5 middle tunnel for Waterwall.

It accepts SOCKS5 control traffic from its previous node, negotiates either
username/password authentication through an existing `AuthenticationClient` or
explicit no-auth mode, then either:

- opens a normal Waterwall upstream connection for `CONNECT`, or
- creates a UDP relay association tied to the accepted TCP control connection for `UDP ASSOCIATE`

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
- Accepts UDP datagrams only for a live, accepted TCP control association.
- Forwards UDP payloads through the configured next node using the requested destination context.
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
- UDP payload is only accepted when the sender matches a live, accepted TCP control association.

## Complete SOCKS5 TCP/UDP Topology Example

```json
{
  "name": "socks5-service",
  "nodes": [
    {
      "name": "socks-entry",
      "type": "TcpUdpListener",
      "settings": {
        "address": "127.0.0.1",
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
        "ipv4": "127.0.0.1"
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

This no-auth example is intentionally bound to loopback. For remote clients,
configure `auth-client-node-name` with an `AuthenticationClient`, then replace
both listener and advertised addresses with addresses appropriate for the
deployment.

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

The resulting user identity is attached to the line together with credential
metadata used by compatible downstream `Router` rules. The internal
`UserController` applies the configured user policy before the line reaches the
configured next tunnel. In no-auth mode no authenticated user identity is
available for user-specific policy, so deployment-level access controls remain
important.

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
drops the datagram, sends no reply, and leaves the TCP control line unchanged. A
callback invoked from a different current worker is instead a
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

Association state is worker-local and uses an opaque dynamic-endpoint identity.
It stores copied metadata rather than a usable pointer to the TCP control line,
and a closing control line removes only its current matching association.

### UDP payload behavior

When a UDP datagram from an accepted association arrives:

- the tunnel validates the SOCKS5 UDP header
- fragmented SOCKS5 UDP packets (`FRAG != 0`) are ignored conservatively
- the requested destination is parsed from the UDP header
- the UDP payload body is forwarded upstream using that destination context

When a reply comes back from the next tunnel:

- the reply payload is wrapped into a SOCKS5 UDP response header
- the source address in that header identifies the remote endpoint associated with that reply
- the wrapped datagram is sent back toward the previous node

### Outbound UDP processing

The client-facing association remains separate from outbound processing and
uses the normal layer-4 callback contract. Association-owned outbound state is
released when the control line closes.

### Finish behavior

The implementation follows normal Waterwall finish ordering:

- control-line teardown marks the line closing before final SOCKS5 bytes, closes the dynamic endpoint, and destroys local state
  before propagating real `Finish` callbacks
- UDP associations are unregistered before the control line is allowed to die
- association-owned outbound state is released before close
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
