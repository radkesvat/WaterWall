# HttpProxyServer

`HttpProxyServer` accepts HTTP/1.0 and HTTP/1.1 forward-proxy requests and CONNECT tunnels. It is a platform-independent L4 middle node:

```text
TcpListener -> HttpProxyServer -> configured outbound chain
```

Listener address and port belong to `TcpListener`. Ordinary requests require an absolute `http://` URI; the proxy forwards origin-form HTTP/1.1 and regenerates Host from that URI. A conflicting valid incoming Host never changes the destination. HTTPS uses CONNECT with an explicit port from 1 through 65535. CONNECT success is sent only after outbound establishment, before destination data; subsequent bytes are opaque.

`HttpClient` and `HttpServer` carry WaterWall traffic inside HTTP framing. They do not provide this forward-proxy interface. Mixed SOCKS/HTTP ports, outbound HTTP proxy negotiation, TLS interception, Upgrade/WebSocket, and HTTP/2 or HTTP/3 proxy interfaces are unsupported. Valid extension methods such as PROPFIND are forwarded; TRACE receives 405. Authenticated `OPTIONS *` and OPTIONS with Max-Forwards zero receive a local empty response and close; forwarded OPTIONS decrements Max-Forwards.

## Settings

| Setting | Default / accepted values |
| --- | --- |
| `no-auth` | false; set true for unauthenticated access, omitting both other selectors |
| `users` | Nonempty array of `{ "username": "...", "password": "..." }`; unlimited, untracked access (warning below) |
| `auth-client-node-name` | Existing AuthenticationClient for tracked accounts; exclusive with users and no-auth true |
| `sweep-interval-ms` | 1000; tracked-mode UserController enforcement interval |
| `max-header-bytes` | 32768; 1024–65536, per request/response header block |
| `max-pending-bytes` | 262144; 65536–1048576, at least the header limit |
| `header-timeout-ms` | 15000; deadline from the first byte of an active incomplete header |
| `connect-timeout-ms` | 30000; child Init through genuine Est, including routing/resolution |
| `idle-timeout-ms` | 300000; no-progress deadline for idle clients, responses, bodies, and relay |
| `verbose` | false; credentials and complete untrusted headers are never logged |

> **Local users warning:** Local `users` provide username/password access only. Their usage is not tracked by WaterWall's user-account system, and no per-user traffic quota, connection/IP limit, bandwidth limit, or account expiry is enforced for these credentials. They have unlimited per-user allowances and can abuse that access or exhaust server resources. Use `auth-client-node-name` for tracked accounts and its supported limits. Proxy buffer limits, timeouts, routing policy, and any separately configured enforcement still apply.

Timeouts and the sweep interval are integers from 1 through 2147483647 milliseconds. Unknown, duplicate, conflicting, missing, and incorrectly typed settings fail startup. Both a previous and next L4 node are required by topology validation.

Fixed limits are an 8192-byte start line, 128 header fields, a 1024-byte chunk-size/extension line, a 16384-byte/64-field trailer section, and 32 informational responses per exchange. Pending content is counted across both directions, including queued rewritten headers. At most four coalesced stream/output allocations are retained, with allocation charge at most four times max-pending-bytes; header parsing/rewrite scratch and credentials have separate bounded storage. Input is processed in streaming slices, so the pending limit is not a body-size limit. Pressure pauses production and resumes below the low watermark; overflow closes the exchange.

## Authentication and accounting

Up to two separately bounded header blocks remain available during chunked bodies so trailer validation also honors Connection-nominated hop-by-hop fields. Each is limited by max-header-bytes and is released when framing completes or the session closes.

Choose exactly one mode: `no-auth: true`, local `users`, or `auth-client-node-name`. For either authenticated mode, `no-auth` may be absent or false. Conflicting selectors, even null or invalid selectors, fail startup; an empty local array never enables unauthenticated access.

Local entries have exactly two required string fields, `username` and `password`. Each contains 1-255 bytes in the parsed string representation, with no control bytes or DEL. Usernames cannot contain a colon; passwords can. Matching is exact and case-sensitive, without trimming or Unicode normalization. Configured and supplied bytes must match, including UTF-8 bytes. Embedded NUL is unsupported; the wire decoder rejects it. The existing cJSON string representation is used. Duplicate exact pairs, duplicate or unknown object fields (including policy fields such as `limit`, `enabled`, or `expire-at-ms`) fail startup. The same username with different passwords, or different usernames with the same password, is allowed; both components must match one entry.

The local list is copied at startup and remains immutable until shutdown. Change it by restarting WaterWall with the new configuration. Live edits, active revocation and hot reload are not provided. Passwords are stored in configuration, and HTTP Basic itself does not encrypt credentials.

Basic `Proxy-Authorization` is checked on every HTTP request, including reused connections. Missing, unsupported, or rejected credentials receive 407 with `Proxy-Authenticate: Basic realm="WaterWall"`, an empty framed body, and Connection close. In tracked mode, an unavailable AuthenticationClient receives 503. Local mode does not consult an account service. Local OPTIONS also authenticates; CONNECT authenticates before creating its child, then relays opaque bytes. Duplicate credential fields are malformed. Credentials are stripped even in no-auth mode; origin Authorization stays origin data.

Base64 must be canonical and valid. Username and password must each contain 1–255 bytes, with no NUL or control bytes; the first colon separates them. Provisioned and supplied bytes must match exactly, including UTF-8 bytes when used. No Unicode normalization or charset conversion is performed. The AuthenticationServer user's `password` field stores the complete `username:password`; its `name` is account metadata.

Only tracked mode inserts an internal UserController. Do not insert another controller manually for this authentication layer. Each new outbound child carries inherited user markers, the validated value handle and credentials, and original source/listener metadata. Tracked admission, accounting, supported limits, and active revocation use the existing controller. CONNECT authenticates once before relay; tracked controller enforcement continues during relay. Local mode follows the configured chain directly and adds exactly one credentials-only marker to each new child, without creating a user handle, account record, usage report, reservation, or per-user enforcement timer. Inherited identities and independently configured policies remain in effect. Neither mode appends repeated markers to the borrowed client or a reused child.

## Streaming, reuse, and routing

Fixed-length and chunked uploads and downloads stream incrementally. Close-delimited responses, HEAD/bodyless responses, informational responses, Expect: 100-continue, and early final responses are supported. An early final response stops upload and closes the client after delivering the response. Hop-by-hop fields are filtered and Via is appended. Origin status, redirects, cookies, challenges, and content are preserved; the proxy does not follow redirects.

Duplicate/list Content-Length, CL with Transfer-Encoding, unsupported transfer coding stacks, folded fields, invalid authority, malformed chunk framing, and prohibited trailers are refused. Full request headers, authority, and authentication are validated before creating a destination. A later body error closes the exchange; an already forwarded prefix cannot be undone. After final response commitment, errors close the connection without appending another response.

One client has at most one live outbound child. Requests execute sequentially, including pipelined input. A completed eligible exchange can reuse its child only for the same requested host/port and authentication mode. Local mode also requires the same complete credential pair; tracked mode requires credential bytes plus user ID/generation. Hostnames compare case-insensitively, IP literals by address; distinct hostnames and trailing DNS dots are not coalesced. A changed destination or identity replaces the child. No failed request is automatically replayed.

Domains are passed into the configured chain; the proxy has no private DNS or socket path. IPv4 literals must be strict dotted decimal, IPv6 literals bracketed, and domain names ASCII/A-labels. Userinfo, fragments, encoded authorities, zone identifiers, ambiguous numeric addresses, and invalid ports are rejected. Escaped path/query bytes retain their meaning.

A controller can replace the outbound section with any compatible chain, including Router or remote tunneling. Requested authority, a locally resolved address, and the final transport peer can legitimately differ. Reused children retain their established route; new children execute normal routing again.

HTTP/1.0 clients get one exchange and close. A single Expect: 100-continue on an ordinary HTTP/1.0 request is ignored and removed before forwarding; its body proceeds without a Continue handshake. Chunked upstream responses are decoded to close-delimited output for them, with trailers dropped. Close-delimited responses and Connection close responses complete before closing the client. The existing TCP adapters turn read EOF into full closure on both POSIX and Windows IOCP; full half-close semantics and new reverse traffic after peer EOF are not promised.

The incoming line is borrowed from its source owner. HttpProxyServer creates, inventories, and destroys its separate outbound child. Worker quiescence detaches timers and disables new work; worker drain closes every owned child independently of source drain order.

## Complete examples

The repository supplies complete `core.json` and `config.json` inputs:

- `tunnels/HttpProxyServer/examples/noauth/`: separate loopback SOCKS port 1080 and HTTP port 8080, with independent connectors.
- `tunnels/HttpProxyServer/examples/local-users/`: standalone loopback HTTP port 8080 with two sample local pairs and no account services or users database.
- `tunnels/HttpProxyServer/examples/authenticated/`: loopback HTTP port 8080, AuthenticationClient/AuthenticationServer, and sample `users.json` with `user:pass`.

Run from the selected example directory so relative config/database paths resolve:

```text
/path/to/Waterwall --restricted-config --config:core.json
```

On Windows, use the absolute path to `Waterwall.exe` with the same arguments from that directory. The public launch identity must meet the Windows launcher's elevation requirements. Native Windows artifact, CPU/OS, IOCP, console, and recovery qualification are separate from this platform-independent node contract.

The `tests/cases/http_proxy/` fixture also demonstrates a Router-selected outbound branch that reaches a sentinel despite an unavailable requested transport endpoint. It exercises both proxy listeners and real authentication without an external node or script in the runtime chain.

### Standalone local-users example

> **Unlimited, untracked access:** Local `users` provide username/password access only. Their usage is not tracked by WaterWall's user-account system, and no per-user traffic quota, connection/IP limit, bandwidth limit, or account expiry is enforced for these credentials. They have unlimited per-user allowances and can abuse that access or exhaust server resources. Use `auth-client-node-name` for tracked accounts and its supported limits. Proxy buffer limits, timeouts, routing policy, and any separately configured enforcement still apply.

The supplied `local-users/config.json` uses `TcpListener -> HttpProxyServer -> TcpConnector` with these proxy settings:

```json
{
  "users": [
    { "username": "alice", "password": "replace-alice-password" },
    { "username": "bob", "password": "replace-bob-password" }
  ]
}
```

From `tunnels/HttpProxyServer/examples/local-users/`, run the built executable with `--restricted-config` (for example, `../../../../build/msvc/Release/Waterwall.exe --restricted-config` on Windows). No AuthenticationClient, AuthenticationServer, or users database is required. Replace the sample passwords before use. With an HTTP origin listening on loopback port 8000:

```sh
curl --noproxy "" --proxy http://127.0.0.1:8080 --proxy-basic --proxy-user alice:replace-alice-password http://127.0.0.1:8000/
```
