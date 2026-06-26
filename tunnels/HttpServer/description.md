<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/HttpServer.mdx, and both files must keep the same documentation version.
-->

# HttpServer Node

`HttpServer` is the inverse of `HttpClient`.

It accepts an HTTP request stream from its upstream side, strips HTTP framing, and forwards only the request body to the next tunnel. In the other direction, it takes response body payload from the next tunnel and wraps it as HTTP/1.1 or HTTP/2.

When `websocket` mode is enabled, it validates a WebSocket opening handshake first and then treats subsequent payload as WebSocket frames instead of HTTP body data.

This tunnel does not terminate TLS by itself. If your wire protocol is HTTPS, you need another tunnel before it that already turned TLS records back into plain HTTP bytes.

## What It Does

- Detects or enforces HTTP/1.1 versus HTTP/2.
- Parses HTTP/1.1 request headers.
- Accepts direct HTTP/2 preface or optional `h2c` upgrade.
- Forwards only request body payload upstream.
- Emits upstream `Finish` when the request body is complete.
- Wraps downstream response payload as HTTP/1.1 chunked response body or HTTP/2 DATA frames.
- Can accept WebSocket over HTTP/1.1 upgrade or direct HTTP/2 extended CONNECT.

This node consumes HTTP request headers and generates HTTP response headers internally.

## Typical Placement

A common layout is:

- `TcpListener`
- optional TLS-decoding tunnel
- `HttpServer`
- some application or payload-processing tunnel

Example:

- `TcpListener -> HttpServer -> SomeServiceTunnel`

or, for decrypted HTTPS traffic:

- `TcpListener -> SomeTlsDecodeTunnel -> HttpServer -> SomeServiceTunnel`

## Configuration Example

```json
{
  "name": "http-server",
  "type": "HttpServer",
  "settings": {
    "http-version": "both",
    "upgrade": true,
    "websocket": false,
    "host": "example.com",
    "path": "/api/upload",
    "method": "POST",
    "status": 200,
    "content-type": "application/json",
    "headers": {
      "cache-control": "no-store",
      "x-powered-by": "waterwall"
    }
  },
  "next": "service-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"HttpServer"`.

### `settings`

There are no tunnel-specific mandatory settings.

If omitted, the current implementation defaults to:

- HTTP mode: `both`
- expected method: `POST`
- expected path: `/`
- response status: `200`

## Optional `settings` Fields

- `http-version` `(number or string)`
  Selects protocol mode.

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

  Current default: `both`

- `upgrade` `(boolean)`
  Only meaningful when `http-version` is `both`.

  If enabled, the server can accept HTTP/1.1 upgrade requests.

  Default upgrade protocol:
  - `Connection: Upgrade, HTTP2-Settings`
  - `Upgrade: h2c`
  - `HTTP2-Settings: ...`

  Default:
  - `true` when `http-version` is `both`
  - `false` otherwise

- `upgrade-protocol` `(string)`
  Optional HTTP/1.1 upgrade protocol token to accept instead of the default `h2c`.

  When this is set to a value other than `h2c`:
  - the server expects `Connection: Upgrade`
  - the server expects `Upgrade: <your-token>`
  - after a successful `101`, the tunnel switches to raw bidirectional byte forwarding

- `upgrade-request-headers` `(object)`
  Optional required headers that must appear on the HTTP/1.1 upgrade request before the upgrade is accepted.

- `upgrade-response-headers` `(object)`
  Optional extra headers to include only on the HTTP/1.1 `101 Switching Protocols` response.

- `host` `(string)`
  Optional expected HTTP `Host`.

  If set, mismatched HTTP/1.1 requests are rejected.

- `path` `(string)`
  Expected request path.
  Default: `"/"`

- `method` `(string)`
  Expected request method.
  Default: `"POST"`

  In `websocket` mode, HTTP method validation switches to the WebSocket rules:
  - HTTP/1.1 requires `GET`
  - HTTP/2 requires extended `CONNECT`

- `status` `(integer)`
  Response status code to send back.
  Default: `200`

  Allowed range in current implementation:
  - `100` to `599`

- `content-type` `(string)`
  Optional response content type emitted automatically.

  It is matched against Waterwall's internal content-type table.

- `headers` `(object)`
  Extra response headers.

  Each key is the header name and each value must be a string.

- `websocket` `(boolean)`
  Enables WebSocket mode.
  Default: `false`

  When enabled:
  - HTTP request-body parsing is replaced with WebSocket frame parsing after handshake success
  - downstream payload buffers are sent as WebSocket binary frames
  - downstream `Finish` sends a WebSocket close frame before the real Waterwall finish

- `websocket-origin` `(string)`
  Optional expected `Origin` value for the WebSocket opening handshake.

- `websocket-subprotocol` `(string)`
  Optional subprotocol to require and echo back in the handshake response.

- `full-duplex` `(boolean)`
  Keeps HTTP request-end from being reflected into Waterwall upstream `Finish`.
  Default: `false`

  When enabled:
  - HTTP/1.1 request-body completion is tracked internally
  - direct HTTP/2 or upgraded h2c request `END_STREAM` is tracked internally
  - the service-facing Waterwall line remains open until the real transport line finishes

  This is the mode to use when you want plain HTTP/1.1 or h2c to behave more like a bidirectional transport instead of a strict request-end-driven service boundary.

- `http1-mode` `(string)`
  Selects the HTTP/1.1 transport shape.

  Supported values:
  - `"single"`: the existing one-connection HTTP/1.1 behavior
  - `"split"`: pair separate upload and download HTTP/1.1 connections into one logical Waterwall line

  Default: `"single"`

- `split` `(object)`
  Optional settings for `http1-mode = "split"`.

  Split mode requires `http-version = 1` and cannot be combined with `websocket`.

  Common fields:
  - `upload-method` default: the top-level `method`
  - `download-method` default: `"GET"`
  - `upload-path` default: the top-level `path`
  - `download-path` default: the top-level `path`
  - `id-placement`: `"query"`, `"header"`, `"cookie"`, or `"path"`; default `"query"`
  - `id-name`: default `"wwid"`
  - `direction-placement`: `"query"`, `"header"`, `"cookie"`, or `"path"`; default `"query"`
  - `direction-name`: default `"wwdir"`
  - `upload-value` / `download-value`: default `"upload"` / `"download"`
  - `token`, `token-placement`, `token-name`: optional required shared token metadata

  Path templates may contain `{id}`, `{direction}`, `{cache}`, and `{token}`.

- `verbose` `(boolean)`
  Enables extra debug logging for protocol detection, handshakes, and framing flow.
  Default: `false`

  Rejections and protocol errors are still logged even when this is `false`.

` `no-split-upload-buffering-limit` `(boolean)`
  When enabled, SplitHttp will not close connections if the upload side sends too much data before the corresponding download connection has joined.

  This option is currently considered mainly useful for multi-worker test scenarios, such as http1_bidirectional_tcp_loopback, where the TestClient sends all chunks immediately after the connection is established.
  Default: `false`

## Detailed Behavior

### Lifecycle behavior

On upstream `Init`, `HttpServer`:

- allocates per-line HTTP state
- forwards upstream `Init` to the next tunnel
- chooses its runtime mode according to `http-version`

The runtime protocol rules are:

- HTTP/1.1 mode:
  treat all traffic as HTTP/1.1
- HTTP/2 mode:
  initialize nghttp2 server state immediately
- both mode:
  wait for input and detect whether the stream begins with the HTTP/2 client preface or with an HTTP/1.1 request line

In `websocket` mode:

- HTTP/1.1 expects the normal WebSocket upgrade request
- direct HTTP/2 expects extended `CONNECT` with `:protocol = websocket`
- the HTTP/1.1 `Upgrade: h2c` path is not used as the WebSocket handshake

### HTTP/1.1 request handling

For HTTP/1.1, `HttpServer` parses request headers internally.

It validates:

- method
- path
- optional host

If validation fails, the tunnel closes the line instead of generating an application-level error response.

Supported request body styles are:

- chunked transfer encoding
- fixed `Content-Length`
- no body

Behavior after header parsing:

- no body:
  with `full-duplex = false`, the next tunnel immediately receives upstream `Finish`
- `Content-Length` body:
  exactly that many bytes are forwarded upstream
- chunked body:
  chunk framing is removed and chunk payload is forwarded upstream

Trailer blocks are consumed internally.

With `full-duplex = true`:

- request-body completion is remembered internally instead of immediately sending Waterwall upstream `Finish`
- response bytes may continue to flow downstream on the same line
- chunked HTTP/1.1 requests can therefore behave like a long-lived bidirectional transport

### Split HTTP/1.1 mode

With `http1-mode = "split"`, `HttpServer` treats incoming HTTP/1.1 connections as transport halves:

- upload request: its request body is decoded and forwarded upstream
- download request: it receives the response body as a chunked HTTP/1.1 response

The server pairs both halves by the configured identifier and direction metadata, then creates one normal Waterwall line toward the next node. The download response headers may be sent before the upload half arrives, which keeps CDN/proxy download requests visibly active.

Example:

```json
{
  "http-version": 1,
  "http1-mode": "split",
  "path": "/tunnel",
  "split": {
    "upload-method": "POST",
    "download-method": "GET",
    "id-placement": "query",
    "id-name": "sid",
    "direction-name": "part",
    "token": "shared-edge-token",
    "token-placement": "header",
    "token-name": "X-Tunnel-Token"
  },
  "headers": {
    "Cache-Control": "no-store"
  }
}
```

For path-template pairing:

```json
{
  "http-version": 1,
  "http1-mode": "split",
  "split": {
    "upload-path": "/u/{id}",
    "download-path": "/d/{id}/{cache}",
    "id-placement": "path"
  }
}
```

### WebSocket handling

When `websocket` mode is enabled:

- HTTP/1.1 returns `101 Switching Protocols`
- HTTP/2 returns `:status = 200`
- WebSocket text, binary, and continuation frames are forwarded upstream as plain payload bytes
- client masking is validated and removed internally
- ping and pong are handled internally
- close frames are converted into Waterwall `Finish`
- HTTP/1.1 upgrade requests that carry a body are rejected conservatively

### HTTP/1.1 response handling

For HTTP/1.1 responses, `HttpServer` always emits:

- a status line using the configured `status`
- `Connection: close`
- `Transfer-Encoding: chunked`

So downstream response payload from the next tunnel is always turned into chunked HTTP/1.1 response body data.

When the next tunnel finishes:

- headers are sent if they were not already sent
- the final `0\r\n\r\n` chunk is sent
- downstream `Finish` is propagated toward the previous tunnel

### Direct HTTP/2 behavior

For direct HTTP/2, `HttpServer` creates an nghttp2 server session and accepts a single request stream per line.

Current session settings include:

- `MAX_CONCURRENT_STREAMS = 1`
- `INITIAL_WINDOW_SIZE = 1 MiB`
- `MAX_FRAME_SIZE = 32 KiB`

Request DATA frames are forwarded upstream as plain payload.
`END_STREAM` on the request becomes upstream `Finish` only when `full-duplex = false`.

Incoming HTTP/2 bytes are fed to nghttp2 in 16 KiB slices. This is intentionally smaller than 32 KiB so large Waterwall
buffers cannot trigger old nghttp2 receive-side stalls observed with oversized `nghttp2_session_mem_recv2()` calls.

Response payload from the next tunnel is turned into HTTP/2 DATA frames on the same stream.
Response headers are generated internally from the configured `status`, `content-type`, and `headers`.

Extra streams can be rejected with `RST_STREAM REFUSED_STREAM`.

### `h2c` upgrade behavior

When `http-version` is `both` and `upgrade` is enabled, the server can accept a valid HTTP/1.1 upgrade request.

For default `h2c`, the current code requires these pieces together:

- `Connection: Upgrade`
- `Connection: HTTP2-Settings`
- `Upgrade: h2c`
- `HTTP2-Settings: ...`

If present:

- the tunnel sends the HTTP/1.1 switching-protocols response
- decodes the peer's `HTTP2-Settings`
- upgrades nghttp2 state
- leaves stream `1` as the original upgraded request and waits for the client's single post-upgrade HTTP/2 tunnel stream

If the original upgrade request already carries an HTTP/1.1 body, the upgrade is ignored conservatively and the line stays on ordinary HTTP/1.1 parsing.

If `upgrade-protocol` is set to a non-`h2c` value instead:

- the tunnel validates that custom `Upgrade:` token
- validates any configured `upgrade-request-headers`
- sends `101 Switching Protocols`
- adds any configured `upgrade-response-headers`
- then forwards bytes bidirectionally without further HTTP body framing

### Data ownership at tunnel boundaries

`HttpServer` forwards only request and response bodies across tunnel boundaries.

That means:

- request headers are not sent to the next tunnel
- response headers are not expected from the next tunnel
- lifecycle events are used to mark end-of-request and end-of-response

## Notes And Caveats

- `HttpServer` is an HTTP framing tunnel, not a TLS tunnel.
- HTTP/1.1 request validation checks method, path, and optional host.
- Current HTTP/2 code is single-stream oriented and does not expose request metadata to the next tunnel.
- HTTP/2 request validation checks method, path, and optional authority/host before forwarding body bytes.
- In WebSocket mode, handshake-critical headers are generated by the tunnel and conflicting duplicates from `headers` are ignored.
- Response headers are always generated by this tunnel; the next tunnel supplies only response body payload and finish events.
- Automatic `Content-Type` emission only works for content types recognized by Waterwall's internal table. For custom values, add the header manually in `headers`.
- This tunnel reserves `required_padding_left = 16` so HTTP/1.1 chunks and small tunnel frames can prepend protocol bytes efficiently. HTTP/2 DATA is emitted through nghttp2, not hand-packed into caller buffers.
