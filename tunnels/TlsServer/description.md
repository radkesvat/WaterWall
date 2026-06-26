<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/tls-server.mdx, and both files must keep the same documentation version.
-->

# TlsServer Node

`TlsServer` is a server-side TLS wrapper built on OpenSSL.

It accepts encrypted TLS bytes from the previous node, performs a real TLS server handshake, decrypts application data, and forwards the resulting cleartext to the next node. In the other direction, it takes cleartext payload from the next node, encrypts it into TLS records, and sends those records back to the previous node.

This tunnel is meant to behave like a basic nginx `stream` TLS server, not like nginx `http`. It does not know anything about HTTP, HTTP/2, or any application protocol placed after it in the chain.

## What It Does

- Creates one TLS server session per Waterwall line.
- Performs a real OpenSSL server handshake.
- Decrypts upstream TLS records into cleartext for the next node.
- Encrypts downstream cleartext into TLS records for the previous node.
- Optionally rejects handshakes by exact SNI match.
- Optionally selects ALPN from a configured server-preference list.
- Optionally sends non-TLS first bytes to a fallback node instead of returning TLS failure behavior.
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
    "select-alpns": ["http/1.1"],
    "session-cache": "none",
    "session-tickets": true,
    "fallback-node-name": "nginx-tls-fallback",
    "fallback-intentional-delay-ms": 7,
    "fallback-intentional-delay-jitter-ms": 1,
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
  Optional exact-match SNI gate.

  If set, clients that do not send this exact SNI are rejected during handshake. This is only a filter; it does not change certificates dynamically.
  This setting is incompatible with `fallback-node-name` because SNI mismatch can reject an otherwise valid ClientHello
  before ServerHello.

- `alpns` `(array of strings)`
  Deprecated alias for an ALPN selection list and server preference order. Prefer `select-alpns`.

  The array order is the server preference order. For example, `["h2", "http/1.1"]` selects `h2` when the client offers
  both values. This setting no longer acts as a handshake gate: if there is no overlap with the client offer, the TLS
  handshake continues without negotiated ALPN.

- `select-alpns` `(array of strings)`
  Optional ALPN selection list and server preference order.
  Default: `["http/1.1"]` when neither `alpns` nor `select-alpns` is configured.

  The array order is the server preference order. `TlsServer` selects the first configured value also offered by the
  client. If the client sends an ALPN extension but there is no overlap, the handshake continues without negotiated
  ALPN. If the client sends no ALPN extension, OpenSSL does not invoke the selection callback and the handshake also
  continues with no negotiated ALPN.

  `select-alpns` has three distinct modes:

  | Configuration | Behavior |
  | --- | --- |
  | omitted | Uses the default `["http/1.1"]`; selects `http/1.1` when the client offers it. |
  | `[]` | Disables ALPN selection completely. The handshake accepts valid TLS, and logs `alpn=<none>` even if the client offered ALPN values. |
  | non-empty array | Selects the first configured value also offered by the client. If nothing overlaps, the handshake continues with `alpn=<none>`. |

  This is useful with `fallback-node-name`, where ALPN selection should reduce fingerprint differences while still
  avoiding ALPN as an active rejection gate. Choose values that match the traffic your protected or fallback chain can
  plausibly answer; selecting `h2` while the selected chain behaves like HTTP/1.1 is fingerprintable. `select-alpns`
  cannot be combined with deprecated `alpns`.

  The empty-array mode intentionally preserves the old no-ALPN-selection behavior for deployments that want a generic
  TLS server which never negotiates ALPN, even when clients offer it. That can be useful when matching a non-HTTP TLS
  service, a weak-probe environment, or an intentionally minimal TLS endpoint.

  Only configure `["h2", "http/1.1"]` when the public fallback path can answer HTTP/2 and the protected proxy protocol
  is also shaped appropriately. In particular, use multiplexing in the proxy protocol when advertising `h2`; otherwise
  client activity that creates many separate TLS/HTTP/2 connections instead of sharing streams can become fingerprintable.

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

- `handshake-timeout-ms` `(number, milliseconds)`
  Hard deadline for the TLS handshake to complete after upstream `Init`.
  Default: `60000`

  Set to `0` to disable the hard handshake deadline. This is not refreshed by received bytes. It is separate from
  listener idle settings such as `TcpListener`'s `initial-idle-timeout-ms` and `active-idle-timeout-ms`.

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

- `fallback-node-name` `(string)`
  Optional node name that receives the connection when the first upstream bytes are clearly not TLS before `TlsServer`
  has committed to TLS.

  Aliases: `fallback-node`, `fallback`

  This is useful when the same public port should behave plausibly for malformed or plaintext probes. The recommended
  fallback is usually another real TLS server, ideally nginx configured with TLS settings that closely match this
  `TlsServer`.

  Do not combine fallback with `sni`; tunnel creation rejects that configuration. `select-alpns` and deprecated `alpns`
  are allowed with fallback because ALPN mismatch no longer rejects the TLS handshake.

- `fallback-intentional-delay-ms` `(number, milliseconds)`
  Delay applied to upstream payloads sent to the fallback branch.
  Default: `7`

  The fallback branch still receives `Init` immediately. Only payload is delayed. This small delay exists to reduce
  timing-based active-probe fingerprints where a detector compares how quickly a plaintext probe is handed to fallback.
  Set to `0` to disable the intentional delay.
  Delayed fallback payloads are delivered in FIFO order. If upstream `Finish` arrives while fallback payloads are
  delayed, `TlsServer` forwards that `Finish` only after the delayed payloads have been delivered.

  This value must be calibrated against the public behavior the fallback should resemble. The important question is
  whether the fallback branch would answer faster or slower than that behavior, not whether it is co-located or remote.
  A co-located fallback can still be too fast when the protected path normally includes an upstream round trip, such as
  proxy-like traffic fetching remote content, so a positive delay may be appropriate. A remote fallback may already carry
  enough latency, and a local-service imitation may be closer with `0`. Measure the target behavior; delay and jitter are
  mitigations, not proof of timing indistinguishability.

- `fallback-intentional-delay-jitter-ms` `(number, milliseconds)`
  Random jitter applied to delayed fallback payload scheduling.
  Default: `1`

  When `fallback-intentional-delay-ms` is non-zero, each delayed FIFO drain is scheduled in the range
  `max(0, delay - jitter)` through `delay + jitter` milliseconds. If `fallback-intentional-delay-ms` is `0`, jitter is
  ignored because fallback payloads are forwarded immediately.

- `verbose` `(boolean)`
  Enables detailed TLS lifecycle debug logs.
  Default: `false`

  Handshake success logs and handshake failure/rejection reasons are still emitted without this flag.

## Detailed Behavior

### Handshake and data flow

On upstream `Init`, `TlsServer` creates per-line OpenSSL state. Without fallback it forwards upstream `Init` to the next
node immediately. With fallback configured, it waits until the first bytes show whether the line belongs to the protected
TLS branch or the fallback branch.

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

### Fallback behavior

When `fallback-node-name` is set, `TlsServer` keeps only the tiny initial prefix needed to classify the connection before
TLS commit.

If OpenSSL produces a ServerHello, `TlsServer` treats the connection as real TLS, discards the saved copy, starts the
protected `next` branch, and continues the normal TLS handshake.

If the first bytes are clearly not TLS, `TlsServer` releases its TLS state and initializes the fallback node. It then
sends the saved bytes to fallback unchanged after the configured fallback delay and jitter. From that point onward,
payloads in both directions are passed through the fallback branch without TLS encryption or decryption; upstream payloads
keep using the same intentional fallback delay so byte ordering is preserved.

If the first bytes look like a TLS handshake record, for example they start with `16 03`, the connection stays on the
OpenSSL path. Malformed, oversized, incomplete, or slow TLS-looking handshakes are closed by OpenSSL failure or by
`handshake-timeout-ms`; they are not routed to fallback.

The fallback delay is applied only to upstream payloads. Downstream responses from fallback are not intentionally delayed,
and an upstream `Finish` waits behind queued delayed fallback payloads. That is internally consistent with request
handoff, but it still creates a measurable request-side offset. Delay and jitter are only mitigations; they do not prove
timing indistinguishability. Measure the deployment path and choose values that match the service being impersonated.

Fallback is intentionally incompatible with `sni`. If that gate rejects an otherwise valid TLS ClientHello before
ServerHello, forwarding the raw ClientHello to fallback as plaintext can produce a non-TLS response to a valid TLS probe.
That is highly fingerprintable. ALPN selection is allowed with fallback because ALPN mismatch no longer rejects the TLS
handshake or routes the connection to fallback. When fallback is used for probe resistance, enforce access in an inner
protocol layer such as Trojan or VLESS authentication instead of using `TlsServer` SNI gates.

Fallback only controls what happens after bytes arrive and can be classified. Idle timing before classification is still
governed by the listener in front of `TlsServer`, usually `TcpListener`. Handshake timing after `TlsServer` initializes is
controlled by `handshake-timeout-ms`, and listener idle timeouts are not a replacement for that hard handshake deadline.
If you are matching a public fallback TLS server, also match listener idle timing: either tune that server to Waterwall's
listener values or set `TcpListener`'s `initial-idle-timeout-ms` and `active-idle-timeout-ms` to values that fit the
service you are imitating.

Fallback `Est` is forwarded only if the line has not already been established. This prevents duplicate `Est` callbacks
while still allowing fallback to provide the first `Est` in chains where the protected branch would not establish until
after application data is routed.

The best fallback target is generally not a plain HTTP service. For the strongest camouflage, route fallback to a real
nginx TLS server with certificate, SNI, ALPN, cipher, session-ticket, and protocol-version behavior close to this
`TlsServer`. This lets nginx handle invalid traffic with its own public-facing behavior. In particular, when a client
sends plaintext HTTP to an nginx TLS port, nginx usually returns its recognizable HTML "plain HTTP request was sent to
HTTPS port" error page instead of only closing the connection. Forwarding pre-ServerHello probes to that kind of fallback
helps avoid a fingerprint where Waterwall closes or alerts differently from nginx.

Fallback health is also part of the public fingerprint. A down fallback, immediate connection close, generic proxy error,
mismatched headers or body, mismatched certificate behavior, or mismatched timing can all identify the deployment even if
the handoff logic is correct.

### Finish behavior

For clean downstream closes, `TlsServer` sends a TLS `close_notify` alert, flushes it, and then propagates Waterwall finish downstream.

If the peer sends a clean TLS shutdown, `TlsServer` treats that as a clean finish toward the next node.

Fatal TLS failures still close the line in both directions.

## Notes And Caveats

- `TlsServer` is a generic TLS tunnel, not an HTTP tunnel.
- It does not inspect or coordinate with `HttpServer`, `HttpClient`, or any other application-layer tunnel.
- `sni` is only a reject filter in the current implementation. It does not select different certificates.
- If neither ALPN setting is configured, `TlsServer` defaults to HTTP/1.1-only
  `select-alpns: ["http/1.1"]`.
- To intentionally keep the old always-`alpn=<none>` behavior, configure `select-alpns: []`.
- ALPN is selection-only in `TlsServer`; it is not an access gate. No-overlap ALPN offers continue without negotiated
  ALPN.
- `alpns` is a deprecated alias. `select-alpns` is the preferred ALPN selection setting. Neither setting tells later
  tunnels what application protocol was chosen.
- `session-cache` defaults to nginx-like `none`, not builtin caching.
- fallback is selected only before ServerHello. After TLS is committed, later TLS errors stay on the TLS path and do not
  switch to fallback.

## Nginx Matching Warning

This tunnel tries to look like a basic nginx `stream` TLS server with stock settings.

If you change settings away from the defaults, the handshake may still be valid TLS but it may no longer look like stock nginx to active probes or middle-boxes.

Common examples:

- changing `ciphers`
- changing `min-version` or `max-version`
- enabling `prefer-server-ciphers`
- changing `session-cache` away from `none`
- disabling `session-tickets`
- changing ALPN selection
- adding an `sni` filter

So if your goal is wire-level similarity to default nginx, keep the defaults unless you have a specific reason to change them.
