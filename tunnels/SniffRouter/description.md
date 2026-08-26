<!--
Documentation version: 154
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
- otherwise, including non-HTTP traffic and HTTP traffic with no matching host,
  the connection continues to the node's normal top-level `next`.

This makes it possible to share one TLS port between multiple HTTP backends and
a default tunnel/fail path.

Most HTTP Host and TLS SNI configurations can also be expressed with the more
flexible [`Router`](../Router/description.md) node. Start with `SniffRouter` when
you want the shorter domain-to-destination configuration shown here. Use
`Router` when you need HTTP/2 or HTTP/3 sniffing, richer matching, combined rule
conditions, or more flexible routing behavior.

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
| `domains` | string or array of strings | yes | domain patterns for HTTP/1 Host and TLS SNI matching |
| `detection` | string or array of strings | no | omitted means both `["http1", "tls"]`; set one value explicitly to restrict the route to one method |
| `next` | string | yes | target node name for matching connections |

`domain` may be used instead of `domains` for a single domain. `target` is
accepted as an alias for route `next`.

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

## Advanced: Reverse-Tunnel Handshake Routing

This feature is only for a reverse-tunneling topology that contains
`ReverseClient` and `ReverseServer`. It is not a general traffic-direction
setting. `ReverseClient` creates spare outbound links and supplies a private
handshake at the start of each link; ordinary chains without these nodes do not
supply that handshake and should not configure this detector.

It is useful when one decrypted TLS entry point carries both those spare links
and a camouflage website with the same SNI:

```text
TcpListener -> TlsServer -> SniffRouter
                              |-- private link handshake -> ReverseServer
                              `-- default next           -> TcpConnector nginx
```

Advanced settings:

| key | type | required | description |
|-----|------|----------|-------------|
| `reverse-secret-length` | integer | no | private handshake length; default `640`, valid range `1` to `1024` |
| `reverse-secret` | ASCII string | no | XOR secret used to derive the private handshake; must match both peer nodes |

Use `"detection": "reverse"` on the route. `"reverse-tls"` and
`"reverse-handshake"` are aliases. A route using only this detector may omit
`domain`/`domains`, and supplied domain patterns are ignored. If it is combined
with `http1` or `tls`, domains remain required for those matching methods.

```json
{
  "name": "sniff-router",
  "type": "SniffRouter",
  "settings": {
    "reverse-secret-length": 640,
    "reverse-secret": "shared-secret",
    "routes": [
      {
        "detection": "reverse",
        "next": "reverse_server"
      }
    ]
  },
  "next": "camouflage_site"
}
```

The default signature is 640 bytes of `0xFF`. SniffRouter derives customized
bytes exactly as `ReverseClient` and `ReverseServer` do, so all three nodes must
use identical settings. Put SniffRouter after TLS termination: the handshake
must start at byte zero of the decrypted stream. SniffRouter replays it intact,
and `ReverseServer` re-validates and strips it. A partial first-payload prefix
logs a warning and immediately uses top-level `next`; a fronting proxy's
PROXY-protocol header must be stripped before SniffRouter. `Router` does not
currently provide this detector.
