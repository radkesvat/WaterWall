# SniffRouter

A layer-4 content router. It can be placed **right after a `TlsServer`**
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
| `detection` | string or array of strings | no | `http` by default; use `tls`, `client-hello`, or `tls-client-hello` for SNI routing; use `reverse` (aliases `reverse-tls`, `reverse-handshake`) for reverse-link routing; combine in an array, e.g. `["http", "tls"]` |
| `next` | string | yes | target node name for matching connections |

`domain` may be used instead of `domains` for a single domain. `target` is
accepted as an alias for route `next`. `domains` is ignored for a route whose
only detection mode is `reverse`, and may be omitted there.

The node itself must define top-level `next`, which is the default fallback.
Routes are checked in order; the first matching domain wins.

## Example

```json
{
    "name": "sniff-router",
    "type": "SniffRouter",
    "settings": {
        "routes": [
            {
                "domains": ["a.x.com", "b.x.com", "x.com"],
                "next": "node_x"
            },
            {
                "domains": ["*.mydomain.com", "*.mydomain2.com"],
                "next": "node_one"
            }
        ]
    },
    "next": "default_fail_path"
}
```

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
