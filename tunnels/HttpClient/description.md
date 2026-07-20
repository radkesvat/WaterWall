<!--
Documentation version: 109
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/HttpClient.mdx, and both files must keep the same documentation version.
-->

# HttpClient Node

`HttpClient` is a stream tunnel that wraps Waterwall payload into an HTTP request on the upstream side and unwraps the HTTP response body on the downstream side.

It can speak HTTP/1.1, direct HTTP/2, or start as HTTP/1.1 and upgrade to `h2c`.

When `websocket` mode is enabled, the tunnel uses HTTP only for the opening handshake and then carries Waterwall payload as WebSocket binary frames.

This node only formats HTTP. It does not create TLS by itself, so if you really want HTTPS on the wire you normally place `TlsClient` after it.

## What It Does

- Builds an HTTP request from tunnel configuration.
- Sends request headers during `Init`.
- Encodes upstream payload as HTTP request body.
- Decodes downstream HTTP response framing and forwards only the response body.
- Can switch to WebSocket framing after a successful HTTP handshake.
- Supports HTTP/1.1 chunked transfer for request bodies.
- Supports a single HTTP/2 stream per Waterwall line.
- Can attempt HTTP/1.1 to HTTP/2 cleartext upgrade with `Upgrade: h2c`.

This tunnel consumes HTTP headers internally. The previous tunnel sees body payload and lifecycle events, not raw HTTP header blocks.

## Typical Placement

A common layout is:

- some payload-producing tunnel
- `HttpClient`
- optional `TlsClient`
- `TcpConnector`

Examples:

- cleartext HTTP: `SomeTunnel -> HttpClient -> TcpConnector`
- HTTPS-like transport: `SomeTunnel -> HttpClient -> TlsClient -> TcpConnector`

## Matching HttpClient To TlsClient ALPN

When `TlsClient` follows `HttpClient`, the configured HTTP version and the protocols offered through TLS ALPN must
agree. `HttpClient` selects its wire protocol from `http-version`; it does not receive the server's negotiated ALPN from
`TlsClient` and cannot switch modes after the TLS handshake. The user is responsible for keeping both nodes consistent.

Use these pairings when you need a deterministic one-protocol offer:

- HTTP/1.1, HTTP/1.1 split mode, or classic WebSocket Upgrade: configure `HttpClient` for HTTP/1.1 and configure
  `TlsClient` with only `"alpns": ["http/1.1"]`.
- Direct HTTP/2, including WebSocket over HTTP/2 extended `CONNECT`: configure `HttpClient` for HTTP/2 and configure
  `TlsClient` with only `"alpns": ["h2"]`.

For WebSocket over HTTP/2, use `"http-version": 2` together with `"websocket": true`. This selects the extended
`CONNECT` path. Use HTTP/1.1 instead only when the peer expects the classic `GET`/`101 Switching Protocols` upgrade.

Offering both `h2` and `http/1.1` in `TlsClient` is valid, commonly used, and closer to Chrome's default ClientHello.
When using that offer, the user must know which protocol the target server will select and configure this `HttpClient`
for that version. For example, an ordinary Cloudflare-proxied HTTPS hostname with HTTP/2 enabled selects `h2` when it is
offered, so `HttpClient` should use HTTP/2. If the target's choice is unknown or can vary, offer only the protocol that
matches `HttpClient`.

`http-version: "both"` and its aliases do not solve this problem. They implement an HTTP/1.1-to-`h2c` application-layer
upgrade and do not follow the TLS ALPN result. Choose an explicit HTTP version when `TlsClient` is next in the chain.

**Cloudflare caution (as of July 2026):** The `h2` assumption above applies to ordinary HTTPS, not WebSocket.
Cloudflare's currently documented proxied WebSocket behavior does not support HTTP/2 WebSocket extended `CONNECT`
(RFC 8441). For Cloudflare WebSocket, configure `HttpClient` for HTTP/1.1 WebSocket Upgrade and configure the following
`TlsClient` with only `"alpns": ["http/1.1"]`. Offering both makes Cloudflare select `h2`: an HTTP/1.1 `HttpClient`
would then mismatch the negotiated protocol, while an HTTP/2 `HttpClient` would enter the unsupported extended `CONNECT`
path. Re-check Cloudflare's current capabilities before depending on either behavior, because provider settings and
support can change.

## Configuration Example

```json
{
  "name": "http-client",
  "type": "HttpClient",
  "settings": {
    "host": "example.com",
    "path": "/api/upload",
    "scheme": "https",
    "port": 443,
    "method": "POST",
    "user-agent": "WaterWall/2.0",
    "http-version": 2,
    "content-type": "application/json",
    "headers": {
      "x-client-name": "waterwall",
      "x-mode": "demo"
    }
  },
  "next": "tls-or-transport-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"HttpClient"`.

### `settings`

- `host` `(string)`
  Required request host name.

  This value is used for:
  - the HTTP `Host` header in HTTP/1.1
  - the `:authority` pseudo-header in HTTP/2

## Optional `settings` Fields

- `path` `(string)`
  Request path.
  Default: `"/"`

- `scheme` `(string)`
  Request scheme used in HTTP metadata.
  Default: `"https"`

  Current implementation note:
  this does not enable TLS by itself. It only affects HTTP metadata and the default port selection.

- `port` `(integer)`
  Request port.

  Default:
  - `443` when `scheme` is `https`
  - `80` otherwise

- `method` `(string)`
  HTTP method.
  Default: `"POST"`

  It must be one of Waterwall's built-in HTTP methods such as:
  - `GET`
  - `POST`
  - `PUT`
  - `HEAD`
  - `PATCH`
  - `DELETE`

  In `websocket` mode this field is ignored:
  - HTTP/1.1 WebSocket uses `GET`
  - HTTP/2 WebSocket uses extended `CONNECT`

- `user-agent` `(string)`
  HTTP `User-Agent` header value.
  Default: `"WaterWall/1.x"`

- `http-version` `(number or string)`
  Selects request protocol mode.

  Supported values:
  - `1`
  - `2`
  - `"1.1"`
  - `"http1"`
  - `"http1.1"`
  - `"2"`
  - `"http2"`
  - `"h2"`
  - `"both"`
  - `"auto"`
  - `"1.1+2"`

  Current default: HTTP/2 mode.

- `upgrade` `(boolean)`
  Only meaningful when `http-version` is `both`.

  If enabled, the tunnel starts with an HTTP/1.1 upgrade request.

  Default upgrade protocol:
  - `Connection: Upgrade, HTTP2-Settings`
  - `Upgrade: h2c`
  - `HTTP2-Settings: ...`

  Default:
  - `true` when `http-version` is `both`
  - `false` otherwise

- `upgrade-protocol` `(string)`
  Optional HTTP/1.1 upgrade protocol token to request instead of the default `h2c`.

  When this is set to a value other than `h2c`:
  - the opening request uses `Connection: Upgrade`
  - the opening request uses `Upgrade: <your-token>`
  - after a successful `101`, the tunnel switches to raw bidirectional byte forwarding

- `upgrade-request-headers` `(object)`
  Optional extra headers to include only on the HTTP/1.1 upgrade request.

- `upgrade-response-headers` `(object)`
  Optional required headers that must appear in the HTTP/1.1 `101` response before the upgrade is accepted.

- `content-type` `(string)`
  Optional content type to emit automatically.

  It is matched against Waterwall's internal content-type table.
  Common accepted examples include:
  - `application/json`
  - `text/plain`
  - `application/octet-stream`
  - `multipart/form-data`

- `headers` `(object)`
  Extra request headers.

  Each key is the header name and each value must be a string.

- `websocket` `(boolean)`
  Enables WebSocket mode.
  Default: `false`

  When enabled:
  - upstream payload buffers are sent as WebSocket binary frames
  - downstream WebSocket frames are unwrapped and forwarded as plain payload
  - upstream `Finish` sends a WebSocket close frame before the real Waterwall finish

- `websocket-origin` `(string)`
  Optional `Origin` header for the WebSocket opening handshake.

- `websocket-subprotocol` `(string)`
  Optional WebSocket subprotocol to request.

- `websocket-extensions` `(string)`
  Optional `Sec-WebSocket-Extensions` header to send.

  Current limitation:
  `HttpClient` does not implement WebSocket extensions internally. If the peer negotiates any extension in the handshake response, the connection is rejected.

- `full-duplex` `(boolean)`
  Optional config-symmetry flag for HTTP transport mode.
  Default: `false`

  Current implementation note:
  `HttpClient` already keeps the HTTP/1.1 request body open with chunked transfer encoding until Waterwall upstream `Finish`, so request and response bodies can stream at the same time without extra client-side state changes. The matching `HttpServer` option controls whether request-end is reflected into Waterwall `Finish`.

- `http1-mode` `(string)`
  Selects the HTTP/1.1 transport shape.

  Supported values:
  - `"single"`: the existing behavior, one HTTP/1.1 connection with chunked request and response bodies
  - `"split"`: two HTTP/1.1 connections, one upload request and one download request

  Default: `"single"`

- `split` `(object)`
  Optional settings for `http1-mode = "split"`.

  Split mode requires `http-version = 1` and cannot be combined with `websocket`.

  Common fields:
  - `upload-method` default: the top-level `method`
  - `download-method` default: `"GET"`
  - `upload-path` default: the top-level `path`
  - `download-path` default: the top-level `path`
  - `upload-headers` / `download-headers`: extra per-half request headers
  - `id-placement`: `"query"`, `"header"`, `"cookie"`, or `"path"`; default `"query"`
  - `id-name`: default `"wwid"`
  - `direction-placement`: `"query"`, `"header"`, `"cookie"`, or `"path"`; default `"query"`
  - `direction-name`: default `"wwdir"`
  - `upload-value` / `download-value`: default `"upload"` / `"download"`
  - `cache-bypass`: default `true`
  - `cache-bypass-name`: default `"wwcb"`
  - `token`, `token-placement`, `token-name`: optional shared token metadata

  Path templates may contain `{id}`, `{direction}`, `{cache}`, and `{token}`.

- `verbose` `(boolean)`
  Enables extra debug logging for protocol selection, handshakes, and framing flow.
  Default: `false`

  Rejections and protocol errors are still logged even when this is `false`.

## Detailed Behavior

### Lifecycle behavior

On upstream `Init`, `HttpClient`:

- allocates per-line HTTP state
- forwards upstream `Init` to the next tunnel
- immediately starts request setup based on the selected HTTP mode

The exact startup behavior is:

- HTTP/1.1 mode:
  send request headers right away
- HTTP/2 mode:
  create an nghttp2 client session, submit SETTINGS and request headers, then send the resulting frames upstream
- both plus upgrade:
  send an HTTP/1.1 upgrade request first and wait to see whether the server replies with `101 Switching Protocols`

In `websocket` mode:

- HTTP/1.1 sends a standard WebSocket upgrade request
- direct HTTP/2 waits for `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` and then sends an extended `CONNECT` request
- `http-version = both` plus `upgrade = true` stays on HTTP/1.1 for WebSocket, because the same opening request cannot safely be both `h2c` upgrade and WebSocket upgrade

If `TlsClient` follows this node, the WebSocket path must match the ALPN the target server will select: use HTTP/1.1 with
`["http/1.1"]`, or direct HTTP/2 with `["h2"]`. A Chrome-like offer containing both is also valid when the target's
selection is known and stable, but this tunnel must be configured for that known result because it cannot observe the
TLS server's selection. Cloudflare WebSocket is the exception described above and must be forced to HTTP/1.1.

### Split HTTP/1.1 mode

With `http1-mode = "split"`, `HttpClient` creates two upstream transport lines for each Waterwall line:

- upload line: sends request body chunks to the server
- download line: sends a bodyless request and receives response body chunks

The two HTTP requests carry the same generated identifier plus a direction marker. By default these are query parameters, for example:

```json
{
  "http-version": 1,
  "http1-mode": "split",
  "host": "cdn.example",
  "path": "/tunnel",
  "split": {
    "upload-method": "POST",
    "download-method": "GET",
    "id-placement": "query",
    "id-name": "sid",
    "direction-name": "part",
    "cache-bypass": true,
    "upload-headers": {
      "Cache-Control": "no-store"
    },
    "download-headers": {
      "Accept": "application/octet-stream"
    }
  }
}
```

For path-based IDs:

```json
{
  "http-version": 1,
  "http1-mode": "split",
  "host": "cdn.example",
  "split": {
    "upload-path": "/u/{id}",
    "download-path": "/d/{id}/{cache}",
    "id-placement": "path"
  }
}
```

### HTTP/1.1 request body behavior

For HTTP/1.1, request bodies are always sent as chunked transfer encoding.

That means:

- request headers include `Transfer-Encoding: chunked`
- each upstream payload buffer becomes one or more chunked body pieces
- upstream `Finish` sends the final `0\r\n\r\n` chunk
- response body bytes may arrive before that final chunk, so HTTP/1.1 request and response bodies can stream concurrently on the same connection

For `http-version = both` plus `upgrade = true`:

- if the server accepts `h2c`, Waterwall cancels the original upgraded stream `1`, opens one fresh HTTP/2 tunnel stream, and flushes any payload buffered while waiting for `101` on that tunnel stream
- if a custom `upgrade-protocol` is accepted with `101`, the tunnel switches to raw bidirectional byte forwarding after the HTTP headers

The implementation uses `required_padding_left = 16` so HTTP/1.1 chunks and small tunnel frames can prepend protocol bytes efficiently with `sbufShiftLeft()` when possible. HTTP/2 DATA is emitted through nghttp2, not hand-packed into caller buffers.

### WebSocket behavior

When `websocket` mode is enabled:

- HTTP/1.1 expects `101 Switching Protocols`
- HTTP/2 expects `:status = 200` on an extended `CONNECT`
- Waterwall payload is carried as WebSocket binary frames
- incoming text, binary, and continuation frames are forwarded as plain payload bytes
- ping and pong are handled internally
- close frames are consumed internally and converted to Waterwall `Finish`
- negotiated WebSocket extensions are not supported; if the peer selects any extension, the handshake is rejected

### HTTP/2 behavior

For HTTP/2, `HttpClient` uses nghttp2 and opens a single request stream per Waterwall line.

Current session settings include:

- `MAX_CONCURRENT_STREAMS = 1`
- `INITIAL_WINDOW_SIZE = 1 MiB`
- `MAX_FRAME_SIZE = 32 KiB`

Upstream payload is turned into HTTP/2 DATA frames.
If the remote peer advertises a smaller frame size, payload is split accordingly.

Incoming HTTP/2 bytes are fed to nghttp2 in 16 KiB slices. This is intentionally smaller than 32 KiB so large Waterwall
buffers cannot trigger old nghttp2 receive-side stalls observed with oversized `nghttp2_session_mem_recv2()` calls.

Upstream `Finish` becomes an empty DATA frame with `END_STREAM`, or `END_STREAM` is attached to the last DATA frame when appropriate.

### Upgrade behavior

When `http-version` is `both` and `upgrade` is enabled:

- the tunnel begins with HTTP/1.1
- the request advertises either `Upgrade: h2c` or the configured `upgrade-protocol`
- upstream request payload is buffered until the protocol choice is known

If the response is:

- `101 Switching Protocols` with `Upgrade: h2c`
  the tunnel creates an nghttp2 session, applies the advertised `HTTP2-Settings`, cancels stream `1` because it represents the original HTTP/1.1 upgrade request, submits one fresh HTTP/2 tunnel request, and continues as HTTP/2 on that stream

- `101 Switching Protocols` with a configured non-`h2c` `upgrade-protocol`
  the tunnel stops doing HTTP body framing and continues as raw bidirectional byte forwarding

- a normal non-`101` response
  the tunnel stays in HTTP/1.1 mode and flushes buffered request payload as chunked body data

Unexpected `101` replies are treated as errors.

### Downstream response handling

For HTTP/1.1 responses, `HttpClient` parses headers internally and then forwards only the response body.

Supported response body modes are:

- chunked transfer encoding
- fixed `Content-Length`
- body-until-close
- no body for status codes that forbid one

Special cases handled in the code:

- `1xx` informational responses are skipped
- `204` and `304` are treated as bodyless
- `HEAD` requests are treated as bodyless on response

For HTTP/2 responses:

- HEADERS are consumed internally
- DATA frames are forwarded downstream as plain body payload
- `END_STREAM` becomes downstream `Finish`

## Notes And Caveats

- `HttpClient` does not provide encryption. Pair it with `TlsClient` if you need TLS on the wire.
- When paired with `TlsClient`, match `http-version` to the protocol the target is known to select from `alpns`. If that
  selection is unknown or variable, offer a single protocol; negotiated ALPN is not reported back to `HttpClient`.
- Response headers and status are not exposed to the previous tunnel. Only body payload and finish events are forwarded.
- Extra headers in `headers` are appended to HTTP/1.1 requests as-is.
- In HTTP/2 mode, extra headers whose names start with `:` are ignored.
- In WebSocket mode, handshake-critical headers are generated by the tunnel and conflicting duplicates from `headers` are ignored.
- Automatic `Content-Type` emission only works for content types recognized by Waterwall's internal table. For custom values, add the header manually in `headers`.
- Current implementation is single-stream per line, not a general multi-stream HTTP/2 multiplexer.
