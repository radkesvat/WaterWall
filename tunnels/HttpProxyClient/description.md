# HttpProxyClient Node

`HttpProxyClient` connects through an upstream HTTP/1.1 proxy. It is a Layer 4
middle node with two modes:

- **`connect` (default):** opens a CONNECT tunnel to the target, then carries an
  opaque TCP stream in both directions.
- **`http`:** generates one configured HTTP request, uses upstream application
  bytes as its request body, and returns only the successful response body.

The following transport node connects to the **proxy endpoint**. HttpProxyClient's
`target-address` and `port` select the **origin destination reached through that
proxy**. These are separate addresses.

HTTP mode does not rewrite complete caller-supplied HTTP requests: the preceding
node supplies body bytes only. Use CONNECT when the application already speaks
HTTP, TLS, or another TCP protocol and should retain its own framing.
`HttpProxyServer` provides the incoming forward-proxy interface; `HttpClient`
provides a separate HTTP transport with additional framing modes.

## Typical Placement

```text
TcpListener -> HttpProxyClient -> TcpConnector
TcpListener -> HttpProxyClient -> TlsClient -> TcpConnector
```

The second chain protects the connection to a TLS-enabled proxy. Configure
`TlsClient` for that proxy's certificate name and HTTP/1.1, for example with
`alpns: ["http/1.1"]`. TLS is not inserted automatically.

HTTP mode always requests an absolute `http://` URL. Adding TLS after
HttpProxyClient protects the proxy connection; it does not change the origin
request to HTTPS. For HTTPS to the origin, use CONNECT and let the preceding
application or TLS node supply the origin TLS session inside the tunnel.

## CONNECT Example

This node configuration forwards connections on local port 8443 through the
proxy at `127.0.0.1:8080` to `origin.example:443`:

```json
{
  "name": "http-proxy-connect",
  "nodes": [
    {
      "name": "listen",
      "type": "TcpListener",
      "next": "proxy",
      "settings": { "address": "127.0.0.1", "port": 8443 }
    },
    {
      "name": "proxy",
      "type": "HttpProxyClient",
      "next": "proxy-transport",
      "settings": {
        "mode": "connect",
        "target-address": "origin.example",
        "port": 443
      }
    },
    {
      "name": "proxy-transport",
      "type": "TcpConnector",
      "settings": { "address": "127.0.0.1", "port": 8080 }
    }
  ]
}
```

HttpProxyClient sends `CONNECT origin.example:443 HTTP/1.1`, consumes the proxy's
response header, and releases application bytes after a final 2xx response.
The application must supply TLS itself when the origin expects TLS on port 443.

If an earlier node sets the destination context, use that destination with these
client settings. This example also enables proxy authentication:

```json
{
  "name": "proxy",
  "type": "HttpProxyClient",
  "next": "proxy-transport",
  "settings": {
    "target-address": "dest_context->address",
    "port": "dest_context->port",
    "username": "alice",
    "password": "replace-me"
  }
}
```

The following connector must still address the proxy. Dynamic target values are
captured before that connector can replace the line's destination context.

## One-Request HTTP Examples

To download a body, replace the `proxy` node in the CONNECT example with:

```json
{
  "name": "proxy",
  "type": "HttpProxyClient",
  "next": "proxy-transport",
  "settings": {
    "mode": "http",
    "target-address": "origin.example",
    "port": 80,
    "method": "GET",
    "path": "/download",
    "body-mode": "none"
  }
}
```

Each local connection starts `GET http://origin.example:80/download HTTP/1.1`.
The local application reads the response body without sending its own request.
Sending nonempty upstream data in this example closes the line.

For an upload whose size is known, use:

```json
{
  "name": "proxy",
  "type": "HttpProxyClient",
  "next": "proxy-transport",
  "settings": {
    "mode": "http",
    "target-address": "origin.example",
    "port": 80,
    "method": "POST",
    "path": "/upload?source=waterwall",
    "body-mode": "fixed",
    "content-length": 4096,
    "headers": { "Content-Type": "application/octet-stream" }
  }
}
```

The local application sends exactly 4096 body bytes, possibly across many writes,
then keeps the connection open to read the response. It must not close or
half-close its TCP connection to signal upload completion: WaterWall's TCP source
EOF closes the line. The configured byte count already marks the request end.

## Settings

The node requires `name`, `type: "HttpProxyClient"`, `next`, and a `settings`
object. It belongs between Layer 4 nodes. Setting names and enumerated values
are case-sensitive. Unknown or duplicate settings, wrong types, and conflicting
mode options fail startup.

### Target and Proxy Authentication

| Setting | Default | Meaning |
| --- | --- | --- |
| `mode` | `"connect"` | `"connect"` or `"http"`. |
| `target-address` | Required | Origin IPv4, IPv6, domain, or exactly `"dest_context->address"`; 1–255 bytes. |
| `domain-strategy` | `"do-not-resolve-domains"` | Origin DNS selection; resolving values require CONNECT. |
| `port` | Required | Origin integer port 1–65535, or exactly `"dest_context->port"`. |
| `username`, `password` | Absent | Optional pair for preemptive Basic proxy authentication. Both must be supplied together. |
| `headers` | `{}` | Additional string-valued request headers, in either mode. |
| `verbose` | `false` | Boolean; extra diagnostics without credentials or complete headers. |

`target-address` contains a host or IP, not a URL; the port is separate. IPv6
authorities are bracketed on the wire, and every authority includes its port.
Domain targets use proxy-side DNS by default. Optional `domain-strategy` enables
local origin DNS in CONNECT mode only; HTTP mode preserves the original absolute
URI authority and accepts only omission or `do-not-resolve-domains`.

| `domain-strategy` | CONNECT behavior |
| --- | --- |
| `do-not-resolve-domains` | Default; send the domain to the proxy. |
| `resolve-domains-and-accept-dns-returned-order` | First usable DNS answer. |
| `resolve-domains-and-prefer-ipv4` | Prefer IPv4, falling back to returned IPv6. |
| `resolve-domains-and-prefer-ipv6` | Prefer IPv6, falling back to returned IPv4. |
| `resolve-domains-and-use-only-ipv4` | IPv4 answer required. |
| `resolve-domains-and-use-only-ipv6` | IPv6 answer required. |
| `resolve-domains-with-core-settings` | Use the core DNS selection strategy. |

These exact lowercase strings are required. Unknown, empty, null, non-string,
and duplicate values fail startup. Resolving strategies fail startup in HTTP
mode even for literal targets. Literal IPv4/IPv6 and already-resolved dynamic
IPs bypass DNS, including opposite-family literals: these policies select DNS
answers, not explicit IPs. Preference fallback does not retry proxy requests.

Local DNS runs before the client core Init and following transport Init. The
selected numeric origin and port appear in both CONNECT authority and Host;
IPv6 is bracketed. Configured and dynamic address/port values can be mixed.
The following connector independently selects and resolves the **proxy** with
its own policy. Missing dynamic target values or explicitly UDP, ICMP, or packet
destination protocols close the affected line; an unspecified protocol becomes TCP.

For example, these settings resolve the origin locally:

```json
{
  "mode": "connect",
  "target-address": "origin.example",
  "port": 443,
  "domain-strategy": "resolve-domains-and-prefer-ipv4"
}
```

If DNS selects `192.0.2.20`, the request is
`CONNECT 192.0.2.20:443 HTTP/1.1` with `Host: 192.0.2.20:443`.
The original hostname does not override Host. TLS inside CONNECT is the preceding
application's/node's responsibility: retain the origin hostname for SNI and
certificate verification. TLS after HttpProxyClient authenticates the proxy.

Credentials each contain 1–255 bytes, without control bytes or DEL; the username
also cannot contain `:`. The client sends `Proxy-Authorization: Basic ...` in
its first request and does not retry after an authentication challenge. These
credentials do not become origin `Authorization` or a WaterWall line user
identity. Basic encoding does not encrypt credentials; TLS to the proxy can
protect them in transit.

Additional header names must be valid HTTP tokens and unique ignoring ASCII case.
Values cannot contain CR/LF or other controls except horizontal tab. The node
controls `Host`, `Proxy-Authorization`, `Content-Length`, `Transfer-Encoding`, and
`Connection`. Custom headers also cannot set `Proxy-Connection`, `Keep-Alive`,
`TE`, `Trailer`, `Upgrade`, or `Expect`. Origin `Authorization` and `Content-Type`
are allowed.

### HTTP Request Options

These settings are accepted only with `mode: "http"`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `method` | `"POST"` | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, or `OPTIONS`. |
| `path` | `"/"` | Escaped origin path and optional query, starting with `/`. |
| `body-mode` | `"chunked"` | `"none"`, `"fixed"`, or `"chunked"`; HEAD requires `"none"`. |
| `content-length` | Absent | Required only for `"fixed"`; integer 0–9007199254740991. |

The path cannot contain raw whitespace, non-ASCII bytes, fragments (`#`),
backslashes, or malformed percent escapes. The generated request line is limited
to 8192 bytes, including the method, absolute URI, and HTTP version.
Every HTTP request carries `Connection: close`. Supplying `content-length` with
any body mode other than `fixed` is invalid.

### Limits and Timeouts

| Setting | Default | Meaning |
| --- | --- | --- |
| `max-header-bytes` | `32768` | Integer 1024–65536; limits each response header block and the complete generated request header. |
| `header-timeout-ms` | `15000` | Deadline from the first byte of each incomplete response header block. |
| `connect-response-timeout-ms` | `30000` | CONNECT only: deadline from request-header handoff until final success. |
| `idle-timeout-ms` | `300000` | No-byte-progress deadline, starting at Init and refreshed by payload progress. |

Origin DNS uses the async DNS service timeout/retry policy. Client idle accounting
starts at core Init after origin DNS, so `idle-timeout-ms` excludes that wait but
includes subsequent proxy DNS, connection and handshake waiting.

Timeouts accept integers 1–2147483647 milliseconds; zero does not disable them.
Paused time counts, and expiry closes the line. HTTP mode cannot specify
`connect-response-timeout-ms`; its response waiting is covered by the header
and idle deadlines.

## Request Bodies and Upload Completion

| Body mode | Wire framing | Completion |
| --- | --- | --- |
| `none` | No request body | Header completes the request; nonempty application input closes the line. |
| `fixed` | `Content-Length` | Exactly the configured count completes the upload while leaving the response direction open. |
| `chunked` | `Transfer-Encoding: chunked` | Each nonempty application buffer becomes one chunk; see the completion limitation below. |

Fixed-length accounting spans payload callbacks. A buffer that would exceed the
remaining count is rejected before any of that buffer is forwarded. A zero
content length completes the request at the header. An empty payload callback
never signals end-of-body in any mode.

Chunked encoding puts a hexadecimal size before each piece of body data and a
CRLF after it. It lets the header be sent before the total upload size is known.
The application supplies raw bytes; HttpProxyClient adds chunk framing and
removes it from chunked responses. Chunk boundaries do not need to match TCP
packets or the application's writes.

### Chunked Upload Completion Limitation

**A finite chunked upload cannot finish sending and then wait for a later
response.** WaterWall's `Finish` callback tears down the line; it is not a
send-only completion or TCP half-close signal.

When the source sends `Finish`, HttpProxyClient may send `0\r\n\r\n` to terminate
the chunked request. This happens only if the request header has already been
sent, no older upload buffers or active chunk remain, the next side is writable,
normal dispatch is still allowed, and the response has not already completed.
The node then destroys its state and forwards `Finish`; it does not retain the
line to receive a response. A paused or incomplete upload is closed without a
terminal chunk, and final-byte delivery is not guaranteed.

A terminal HTTP chunk can mark the request end without closing TCP. The
limitation here is the absence of a separate WaterWall signal for “upload
finished, keep receiving,” not a requirement to half-close the proxy connection.

Use `body-mode: "fixed"` when the length is known and the peer answers after the
whole upload. Use `chunked` only with a peer that can respond while the upload
remains open. The proxy must also permit that streaming exchange rather than
buffering the whole request. With HttpProxyServer, a final response cancels an
incomplete upload; the origin should consume the bytes it needs before responding.

## Response and Connection Behavior

The request header is sent as soon as the following Init returns and output is
permitted. There is no first-payload delay, and it does not wait for transport
`Est`. Transport `Est` is forwarded independently and does not mean the proxy
has accepted the request.

CONNECT holds application data until a successful final response, then relays
opaque bytes. HTTP mode can send its body immediately after the request header
and receive a response while uploading. Protocol holds and retained FIFO drains
apply backpressure; an already admitted bounded input may complete after Pause.

Both modes require an HTTP/1.1 final 2xx response and consume up to 32
informational responses internally. HTTP/1.0, `101`/Upgrade, non-2xx finals
(including `407` and redirects), malformed framing, truncation, and exceeded
limits close the line. Proxy response headers and error bodies are not delivered
to the application.

After successful CONNECT, body-framing fields are ignored and subsequent bytes
belong to the tunnel. HTTP mode handles fixed-length, chunked, and
close-delimited response bodies. It validates and discards trailers and does not
decompress `Content-Encoding`; compressed content remains compressed body data.
HEAD and no-content responses produce no application body.

A complete framed HTTP response immediately closes the single exchange,
discards trailing bytes, and cancels any remaining upload. A close-delimited
response ends when the proxy closes its side. Already delivered body bytes
cannot be retracted if later framing or truncation is invalid.

There is no connection pooling or reuse, request pipelining, retry, redirect
following, authentication challenge flow, Upgrade/WebSocket negotiation, HTTP/2,
HTTP/3, UDP support, or built-in TLS. These restrictions describe the proxy
interface; an established CONNECT tunnel does not inspect the protocol inside it.

## Splice and Buffer Limits

Splice requires a supported platform/build, `misc.splice`, and support from every
node in the expanded chain. HttpProxyClient preserves eligible splice buffers
for established CONNECT relay, fixed/chunked uploads, and response buffers wholly
inside a known body-data range. A chunked upload prepends its size to the body
buffer and sends a separate CRLF suffix in FIFO order.

Header/framing input and buffers crossing body boundaries may be fully
materialized into ordinary best-fit storage. HttpProxyClient does not request
ordinary reads by default and handles both ordinary and splice input in all
phases. Adding TlsClient disables splice for the chain. Splice support does not
guarantee zero-copy on every delivery.

With local origin DNS, the internal DomainResolver retains early input in its
separate FIFO: 2 MiB logical bytes and 2 MiB allocation charge, without a separate
1,024-entry cap. It preserves ordinary and pipe-backed buffers, including resident
prefixes. Resolver and client limits apply to separate stages, not one aggregate
connection-memory budget.

Each delivered input is limited to **2 MiB**. Necessary retained input in each
direction shares limits of **2 MiB logical bytes**, **2 MiB queue-capacity
charge**, and **1,024 entries**. Allocation charge includes padding and buffer
overhead, so retention can be refused before reaching the logical byte limit.
Overflow closes the line. These limits bound individual deliveries and pending
storage, not the total size of a streaming body.

Parser limits also include an 8192-byte start line, 128 header fields, a 1024-byte
chunk-size/extension line, and a 16384-byte/64-field trailer section. Header and
framing scratch have separate bounded storage. Materialization can temporarily
add one ordinary input buffer containing up to 2 MiB of payload. These limits
are independent of buffer-pool tiers and kernel pipe capacity and are not a
total process-memory guarantee.

## Node Metadata

| Property | Value |
| --- | --- |
| Node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `10` bytes for a chunk prefix |
