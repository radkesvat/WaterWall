# TlsServer Node

`TlsServer` is a server-side TLS wrapper built on OpenSSL.

It accepts encrypted TLS bytes from the previous node, performs a real TLS server handshake, decrypts application data, and forwards the resulting cleartext to the next node. In the other direction, it takes cleartext payload from the next node, encrypts it into TLS records, and sends those records back to the previous node.

This tunnel is meant to behave like a basic nginx `stream` TLS server, not like nginx `http`. It does not know anything about HTTP, HTTP/2, or any application protocol placed after it in the chain.

## What It Does

- Creates one TLS server session per Waterwall line.
- Performs a real OpenSSL server handshake.
- Decrypts upstream TLS records into cleartext for the next node.
- Encrypts downstream cleartext into TLS records for the previous node.
- Optionally rejects handshakes by exact SNI allow-list match.
- Optionally limits ALPN negotiation to a configured allow-list.
- Supports nginx-like stock defaults for protocol versions, ciphers, tickets, timeout, and soft-off session cache behavior.

## Typical Placement

A common layout is:

- `TcpListener`
- `TlsServer`
- some cleartext protocol tunnel or service tunnel

Example:

- `TcpListener -> TlsServer -> HttpServer`

That arrangement lets:

- `TcpListener` accept TCP connections
- `TlsServer` terminate TLS
- `HttpServer` receive plain HTTP bytes

## Configuration Example

```json
{
  "name": "tls-server",
  "type": "TlsServer",
  "settings": {
    "cert-file": "/etc/waterwall/fullchain.pem",
    "key-file": "/etc/waterwall/privkey.pem",
    "min-version": "TLSv1.2",
    "max-version": "TLSv1.3",
    "ciphers": "HIGH:!aNULL:!MD5",
    "session-cache": "none",
    "session-tickets": true,
    "verbose": false
  },
  "next": "http-server"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TlsServer"`.

- `next` `(string)`
  The next node that should receive decrypted cleartext.

### `settings`

- `cert-file` `(string)`
  Path to the server certificate PEM file.

- `key-file` `(string)`
  Path to the server private key PEM file.

Both fields are required. If either one is missing or invalid, tunnel creation fails.

## Optional `settings` Fields

- `sni` `(string)`
  Optional single-hostname SNI allow-list.

  If set, clients that do not send this exact SNI are rejected during handshake. This is only a filter; it does not change certificates dynamically.

- `snis` `(array of strings)`
  Optional multi-hostname SNI allow-list.

  If set, clients must send one of the listed SNIs or the handshake is rejected with `unrecognized_name`.

  `sni` and `snis` are mutually exclusive.

- `alpns` `(array of strings)`
  Optional ALPN allow-list and server preference order.

  If omitted, `TlsServer` does not constrain ALPN. If set, only listed protocols may be negotiated.

- `min-version` `(string)`
  Minimum TLS version.
  Default: `TLSv1.2`

- `max-version` `(string)`
  Maximum TLS version.
  Default: `TLSv1.3`

  Supported version strings in the current implementation:
  - `TLSv1`
  - `TLSv1.1`
  - `TLSv1.2`
  - `TLSv1.3`
  - `1.0`
  - `1.1`
  - `1.2`
  - `1.3`

- `ciphers` `(string)`
  OpenSSL cipher string for TLS 1.2 and earlier.
  Default: `HIGH:!aNULL:!MD5`

- `prefer-server-ciphers` `(boolean)`
  Enables server cipher preference.
  Default: `false`

- `session-timeout` `(number, seconds)`
  TLS session lifetime.
  Default: `300`

- `session-cache` `(string)`
  Session cache mode.
  Default: `none`

  Supported values:
  - `none`
  - `off`
  - `builtin`
  - `builtin:<size>`

  `shared` is intentionally not supported by the current Waterwall implementation.

- `session-cache-size` `(number)`
  Internal OpenSSL builtin cache size in sessions.
  Default: `20480`

  This only matters when `session-cache` uses `builtin`.

- `session-tickets` `(boolean)`
  Enables or disables TLS session tickets.
  Default: `true`

- `verbose` `(boolean)`
  Enables detailed TLS lifecycle debug logs.
  Default: `false`

  Handshake success logs and handshake failure/rejection reasons are still emitted without this flag.

## Detailed Behavior

### Handshake and data flow

On upstream `Init`, `TlsServer` creates per-line OpenSSL state and forwards upstream `Init` to the next node.

After that:

- encrypted bytes coming from the previous node are fed into the TLS server handshake and record layer
- decrypted application bytes are forwarded upstream to the next node
- cleartext payload coming back from the next node is encrypted and sent downstream to the previous node

This means the next node always sees plain application data, not TLS records.

### `Est` behavior

In Waterwall terms, downstream `Est` still represents the underlying transport becoming established.
`TlsServer` forwards that `Est` immediately; it does not wait for the TLS handshake.

TLS readiness happens later, when the handshake completes.

If the next node sends payload before the handshake is finished, `TlsServer` queues that cleartext and flushes it only after the TLS session is ready.

### Finish behavior

For clean downstream closes, `TlsServer` sends a TLS `close_notify` alert, flushes it, and then propagates Waterwall finish downstream.

If the peer sends a clean TLS shutdown, `TlsServer` treats that as a clean finish toward the next node.

Fatal TLS failures still close the line in both directions.

## Notes And Caveats

- `TlsServer` is a generic TLS tunnel, not an HTTP tunnel.
- It does not inspect or coordinate with `HttpServer`, `HttpClient`, or any other application-layer tunnel.
- `sni` is only a reject filter in the current implementation. It does not select different certificates.
- `alpns` is only a negotiation limit in the current implementation. It does not tell later tunnels what application protocol was chosen.
- `session-cache` defaults to nginx-like `none`, not builtin caching.

## Nginx Matching Warning

This tunnel tries to look like a basic nginx `stream` TLS server with stock settings.

If you change settings away from the defaults, the handshake may still be valid TLS but it may no longer look like stock nginx to active probes or middle-boxes.

Common examples:

- changing `ciphers`
- changing `min-version` or `max-version`
- enabling `prefer-server-ciphers`
- changing `session-cache` away from `none`
- disabling `session-tickets`
- restricting `alpns`
- adding an `sni` filter

So if your goal is wire-level similarity to default nginx, keep the defaults unless you have a specific reason to change them.
