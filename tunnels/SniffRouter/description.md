<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/SniffRouter.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/SniffRouter.mdx, and all files must keep the same documentation version.
-->

# SniffRouter

`SniffRouter` is primarily a simple, convenient layer-4 routing node for common
domain-sniffing setups. It can be placed **right after a `TlsServer`**
(TLS termination) to route by the first decrypted HTTP/1 request, or before TLS
termination to route by the TLS ClientHello SNI.

- if the request `Host` header matches a configured route, the connection is
  handed to that route's `next` node;
- if TLS ClientHello detection is enabled for a route and the SNI matches, the
  connection is handed to that route's `next` node;
- if reverse detection is enabled for a route and the decrypted stream begins
  with the `ReverseClient`/`ReverseServer` reverse-link handshake, the
  connection is handed to that route's `next` node (no domain match needed);
- otherwise, including non-HTTP traffic and HTTP traffic with no matching host,
  the connection continues to the node's normal top-level `next`.

This makes it possible to share one TLS port between multiple HTTP backends and
a default tunnel/fail path.

Most HTTP Host and TLS SNI configurations can also be expressed with the more
flexible [`Router`](../Router/description.md) node. Start with `SniffRouter` when
you want the shorter domain-to-destination configuration shown here. Use
`Router` when you need HTTP/2 or HTTP/3 sniffing, richer matching, combined rule
conditions, or more flexible routing behavior.

The current exception is reverse-link handshake detection: `SniffRouter` can
recognize the handshake sent by `ReverseClient`, while `Router` does not yet
have that detector. Reverse detection is expected to be added to `Router` in
the future, so this is a current capability difference rather than a permanent
architectural distinction.

## How it works

- The top-level `next` is the fallback upstream continuation.
- Each route target is folded into the **same chain** during `onChain`, so it
  gets a per-line state slot and its downstream traffic returns through the
  router to the previous node.
- Upstream `Init` is deferred until the first payload selects a branch. The
  buffered bytes are then replayed to the chosen branch with no loss. This is
  the same for HTTP Host and TLS SNI routing.

## Domain Matching

Domain matching is case-insensitive.

- `example.com` matches exactly `example.com`.
- `*.example.com` matches subdomains such as `www.example.com` and
  `api.edge.example.com`, but not `example.com` itself.
- `*` matches any non-empty Host value.

Host header ports are ignored for matching, so `example.com:443` matches
`example.com`.

HTTP/2 cleartext prefaces do not carry an HTTP/1 `Host` header, so they fall
back to top-level `next` unless routed by some earlier tunnel.

TLS SNI matching uses the same domain patterns as HTTP Host matching. The TLS
ClientHello must arrive within the bounded sniff window.

## Settings

| key | type | required | description |
|-----|------|----------|-------------|
| `routes` | array | no | ordered list of domain routes |
| `reverse-secret-length` | integer | no | reverse handshake length for `reverse` detection; default `640`, valid range `1` to `1024` |
| `reverse-secret` | string | no | XOR secret used to derive the reverse handshake bytes for `reverse` detection |

Each route object:

| key | type | required | description |
|-----|------|----------|-------------|
| `domains` | string or array of strings | required unless detection is reverse-only | domain patterns for this route |
| `detection` | string or array of strings | no | `http1` by default; use `tls` for SNI routing; use `reverse` (aliases `reverse-tls`, `reverse-handshake`) for reverse-link routing; combine in an array, e.g. `["http1", "tls"]` |
| `next` | string | yes | target node name for matching connections |

`domain` may be used instead of `domains` for a single domain. `target` is
accepted as an alias for route `next`. `domains` is ignored for a route whose
only detection mode is `reverse`, and may be omitted there.

The old `http` detection value has been removed and migrated to `http1`.
Former TLS aliases such as `client-hello` and `tls-client-hello` have also been
removed; use `tls`.

The node itself must define top-level `next`, which is the default fallback.
Routes are checked in order; the first matching domain wins.

## Basic domain routing: SniffRouter and Router

For example, on a listener path where no earlier node supplied a destination
domain, this `SniffRouter` sends three HTTP/1 Host names to three separate
destinations:

```json
{
  "name": "sniff-router",
  "type": "SniffRouter",
  "settings": {
    "routes": [
      { "domain": "one.example.com", "next": "destination_one" },
      { "domain": "two.example.com", "next": "destination_two" },
      { "domain": "three.example.com", "next": "destination_three" }
    ]
  },
  "next": "default_destination"
}
```

The equivalent `Router` configuration uses root-level sniffing and domain rule
conditions:

```json
{
  "name": "router",
  "type": "Router",
  "settings": {
    "sniffing": ["http1"],
    "rules": [
      { "destination-domain": "one.example.com", "target": "destination_one" },
      { "destination-domain": "two.example.com", "target": "destination_two" },
      { "destination-domain": "three.example.com", "target": "destination_three" }
    ]
  },
  "next": "default_destination"
}
```

In both forms, entries are checked in order and top-level `next` is the
fallback. The main difference for this basic case is vocabulary: a
`SniffRouter` route uses `domain`/`domains` and `next`, while a `Router` rule
uses `destination-domain` and `target`.

## Reverse-link detection (single-SNI tunnels)

`reverse` detection lets one TLS entry point carry both a `ReverseServer`
reverse tunnel and a real camouflage website without giving the tunnel a
different SNI. Host/SNI routing cannot separate them when everything shares one
SNI, but the reverse link is identifiable by its content: by default,
`ReverseClient` sends a fixed handshake (a 640-byte run of `0xFF`) as the first
bytes of every reverse connection, which does not collide with an HTTP request
or a TLS ClientHello.

If `reverse-secret-length` and/or `reverse-secret` are configured, the reverse
signature is derived the same way as `ReverseClient` and `ReverseServer`: the
default handshake bytes are repeated as needed and XORed with the ASCII bytes of
`reverse-secret` repeatedly. These settings must match the `ReverseClient` and
`ReverseServer` nodes. If they do not match, SniffRouter will not classify the
connection as reverse traffic and will use the default `next` path.

A route with reverse detection matches purely on that signature and ignores
`domains`. Place `SniffRouter` on the **decrypted** stream (i.e. after TLS has
been terminated, whether by an upstream `TlsServer` node or by a fronting proxy
that forwards the plaintext), send the matched route to `ReverseServer`, and let
the top-level `next` fallback serve the camouflage site:

```json
{
    "name": "sniff-router",
    "type": "SniffRouter",
    "settings": {
        "routes": [
            {
                "detection": "reverse",
                "next": "reverse_server"
            }
        ]
    },
    "next": "tcp_to_nginx"
}
```

`SniffRouter` only peeks at the handshake; the buffered bytes are replayed
intact to `ReverseServer`, which re-validates the full handshake and strips it.
A connection that merely starts with `0xFF` but is not a real reverse link is
forwarded to `ReverseServer` and dropped there by the same validation, so it
cannot leak into the tunnel.

The complete reverse handshake must be present in the first payload chunk seen
by `SniffRouter`. If the first payload only contains a prefix of the configured
reverse handshake, `SniffRouter` logs a warning and immediately uses the default
`next` path instead of buffering more bytes.

The handshake must be at the very start of the decrypted stream. If a fronting
proxy forwards traffic with a PROXY-protocol header prepended, strip it before
`SniffRouter` (the leading bytes would otherwise not be the handshake).

## TLS SNI routing and Nginx Camouflage

`SniffRouter` can be placed **before** `TlsServer` to inspect the TLS ClientHello SNI and route matching domains to a protected TLS termination pipeline, while falling back all other connections to a real cover service (such as an nginx HTTPS server).

```text
TcpListener :443 -> SniffRouter
                      |-- route (expected SNI) -> TlsServer -> VlessServer -> ...
                      `-- default (unmatched)  -> TcpConnector -> real nginx :443
```

Configuration example:

```json
{
  "name": "sniff-router",
  "type": "SniffRouter",
  "settings": {
    "routes": [
      {
        "domain": "vpn.example.com",
        "detection": "tls",
        "next": "protected-tls-server"
      }
    ]
  },
  "next": "nginx-fallback-connector"
}
```

### Routing and Buffering Behavior

- **Matching SNI**: Connections presenting a valid TLS ClientHello with an SNI matching the configured domain route to `protected-tls-server`.
- **Default Fallback**: Connections with mismatched SNI, absent SNI, unparseable input, or plaintext HTTP on the TLS port route to top-level `next` (`nginx-fallback-connector`).
- **Stream Replay**: Initial bytes buffered during sniffing are replayed intact to the selected branch in FIFO stream order (callback and TCP packet segmentation are not preserved).
- **8192-byte Sniff Window**: Complete ClientHellos are parsed and classified first, even if larger than 8192 bytes. If an input remains incomplete and the accumulated prefix reaches 8192 bytes, `SniffRouter` stops waiting and selects the default `next` branch.
- **Listener-Owned Idle Timeout**: Incomplete ClientHellos below 8192 bytes remain unassigned. `SniffRouter` does not set an internal timer; the front listener's idle settings (e.g. `TcpListener`) govern the timeout.
- **Why a Real Nginx TLS Fallback**: Routing default traffic to a real nginx HTTPS listener ensures unknown SNI handshakes, no-SNI handshakes, and plaintext HTTP receive authentic nginx responses and error pages (such as HTTP 400 "The plain HTTP request was sent to HTTPS port"), avoiding synthetic handshake rejection fingerprints.
- See `tests/examples/vless_tls_sni_camouflage_server.json` for a complete server example.

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
| `required_padding_left` | `0` bytes |
