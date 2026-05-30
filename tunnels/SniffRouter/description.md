# SniffRouter

A layer-4 content router. It is meant to be placed **right after a `TlsServer`**
(TLS termination) and routes each connection by inspecting the first decrypted
bytes:

- if the bytes look like a normal **HTTP request**, the connection is handed to
  the node named in `web` (typically a `TcpConnector` to a local web server);
- otherwise (binary protocols such as VLESS / VMess / Trojan over raw TCP), the
  connection continues to `next`.

This makes it possible to share a single TLS port between a real website and a
tunnel: a browser that opens the real domain is served locally, while a proxy
client that speaks a binary protocol after the TLS handshake is forwarded into
the tunnel (for example a `Bridge` feeding a `ReverseServer`).

## How it works

- `next` is a normal upstream continuation (the tunnel branch).
- `web` is a second node that the router folds into the **same chain** during
  `onChain` (using `tunnelchainCombine`, the same primitive `Bridge` uses), so
  it gets a per-line state slot and its downstream traffic returns through the
  router to the previous node.
- The decision is made lazily on the first payload; up to 8 bytes are buffered
  and then replayed losslessly to the chosen branch. Upstream `Init` is deferred
  until the branch is chosen so the unused branch is never initialized.

## Detection

A connection is treated as HTTP when the first bytes begin with one of:
`GET `, `POST `, `PUT `, `HEAD `, `DELETE `, `OPTIONS `, `PATCH `, `TRACE `,
`CONNECT `, or `PRI ` (the HTTP/2 connection preface). Anything else is routed to
`next`.

> Note: this byte-sniff assumes the tunnel protocol is **not** itself HTTP-framed
> after TLS (i.e. raw-TCP transports). For WebSocket/gRPC/HTTP-based transports a
> path/host based split should be used instead.

## Settings

| key   | type   | required | description                                                        |
|-------|--------|----------|--------------------------------------------------------------------|
| `web` | string | yes      | name of the node to receive HTTP connections (e.g. a TcpConnector) |

The node must also define `next` (the non-HTTP / tunnel branch).

## Example

```json
{
    "name": "sniff_router",
    "type": "SniffRouter",
    "settings": { "web": "tcp_to_nginx" },
    "next": "bridge_user_side"
},
{
    "name": "tcp_to_nginx",
    "type": "TcpConnector",
    "settings": { "address": "127.0.0.1", "port": 8080, "nodelay": true }
}
```
