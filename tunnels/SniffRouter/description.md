# SniffRouter

A layer-4 content router. It can be placed **right after a `TlsServer`**
(TLS termination) to route by the first decrypted HTTP/1 request, or before TLS
termination to route by the TLS ClientHello SNI.

- if the request `Host` header matches a configured route, the connection is
  handed to that route's `next` node;
- if TLS ClientHello detection is enabled for a route and the SNI matches, the
  connection is handed to that route's `next` node;
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

Each route object:

| key | type | required | description |
|-----|------|----------|-------------|
| `domains` | string or array of strings | yes | domain patterns for this route |
| `detection` | string or array of strings | no | `http` by default; use `tls`, `client-hello`, or `tls-client-hello` for SNI routing; use `["http", "tls"]` to enable both |
| `next` | string | yes | target node name for matching domains |

`domain` may be used instead of `domains` for a single domain. `target` is
accepted as an alias for route `next`.

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
