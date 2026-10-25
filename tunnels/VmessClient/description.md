<!--
Documentation version: 2
Sync note: Keep this file, WaterWall-Docs/docs/02-noderefs/VmessClient.mdx and WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/VmessClient.mdx synchronized.
-->

# VmessClient Node

`VmessClient` sends modern VMess AEAD requests using one configured UUID or short string ID. It carries
TCP streams or fixed-destination UDP datagrams over a byte-stream transport. The
default body security is `aes-128-gcm`. IPv4, IPv6 and domain destinations are supported.

The node's address and port select the **final proxied target**. The following
`TcpConnector` selects the **VMess server endpoint**. TLS and WebSocket belong to
their existing transport nodes; VmessClient does not discover or configure them.

## Placement and examples

```text
TcpListener    -> VmessClient -> TcpConnector
UdpListener    -> VmessClient -> TcpConnector
TcpUdpListener -> VmessClient -> TlsClient -> TcpConnector
TcpListener    -> VmessClient -> HttpClient (WebSocket) -> TcpConnector
TcpListener    -> VmessClient -> HttpClient (WebSocket) -> TlsClient -> TcpConnector
```

For HTTP/1.1 WebSocket over TLS, configure matching HTTP/1.1 ALPN in TlsClient.
Certificate validation and SNI remain TlsClient settings.

```json
{
  "name": "vmess-client",
  "type": "VmessClient",
  "next": "tls-client",
  "settings": {
    "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "address": "example.com",
    "port": 443,
    "protocol": "tcp",
    "security": "aes-128-gcm",
    "domain-strategy": "do-not-resolve-domains",
    "first-payload-timeout-ms": 400,
    "verbose": false
  }
}
```

Here `example.com:443` is the destination requested from the VMess server, even
when the following connector dials a different host and port.

To preserve an incoming proxy/router destination:

```json
{
  "name": "vmess-client",
  "type": "VmessClient",
  "next": "tcp-to-vmess-server",
  "settings": {
    "id": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "address": "dest_context->address",
    "port": "dest_context->port",
    "protocol": "dest_context->protocol",
    "security": "chacha20-poly1305"
  }
}
```

## Settings

| Setting | Default | Accepted values |
| --- | --- | --- |
| `uuid` / `id` / `user-id` | Required | Dashed/compact hexadecimal UUID, or an exact UTF-8 string of 1..30 bytes mapped to UUIDv5 with the nil namespace. |
| `target-address` / `address` / `target` | Required | Literal host/IP, `dest_context->address`, or `line->dest_ctx->address`. Domains contain 1..255 non-NUL bytes. |
| `port` | Required | Integer 1..65535, `dest_context->port`, or `line->dest_ctx->port`. |
| `protocol` / `proto` | `tcp` | `tcp`/`connect`, `udp`/`udp-associate`, `dest_context->protocol`, or `line->dest_ctx->protocol`. |
| `domain-strategy` | `do-not-resolve-domains` | One of the strategies below. |
| `first-payload-timeout-ms` | `400` | Integer 0..4294967295; zero sends an idle request without deliberate waiting after transport Est. |
| `security` | `aes-128-gcm` | `aes-128-gcm`, `chacha20-poly1305`, `auto`, `none`, or `zero`. |
| `chunk-masking` | Mode-dependent | Boolean; true except for `zero`. |
| `global-padding` | Mode-dependent | Boolean; true for encrypted modes, false for `none` and `zero`. |
| `authenticated-length` | `false` | Boolean; encrypted modes only. |
| `encrypted-counter-policy` | `wrap` | `wrap` or `strict`; local policy for each encrypted direction. |
| `send-termination` | `true` | Boolean; send the optional final empty framed record on local close. |
| `packet-encoding` | `none` | `none` or `packetaddr`; packetaddr applies only to UDP. |
| `verbose` | `false` | Reason-coded diagnostics, sampled at most once per second per node, without credentials, keys or plaintext. |

Use exactly one name from each credential/address alias group and at most one
protocol selector. Duplicate JSON keys, conflicting aliases, unsupported settings,
incorrect JSON types and invalid framing combinations fail construction. Setting names
and string values must be valid UTF-8 without embedded NULs. Server-only
user lists, fallback settings, AlterID and legacy authentication settings are not accepted.

Dynamic protocol selection uses exact TCP or UDP. A missing, ambiguous or unsupported
protocol logs a warning and falls back to TCP. A missing dynamic address, invalid or
zero port, or a dynamically selected UDP/`zero` combination closes that association
before transport Init. A fixed UDP/`zero` configuration fails construction.

Short IDs use exact UTF-8 bytes, without trimming, case folding or Unicode normalization.
For example, `waterwall` maps to `106b9dde-356b-5769-b2f6-7ea4193ec5f7`.
Malformed UUID-sized strings and non-UUID IDs longer than 30 bytes are rejected.
A managed VmessServer requires the canonical mapped UUID in AuthenticationClient's
password database; short-name normalization applies to this client and local server
credentials only.

The UUID can be issued by the same management system used by a managed VmessServer.
VmessClient does not depend on AuthenticationClient or UserController, publish that
outbound credential as an authenticated local-peer identity, or duplicate accounting
on its UDP carrier. Admission, quotas, account rotation and user shaping remain on
the server/application side.

## Domains

| `domain-strategy` | Behavior |
| --- | --- |
| `do-not-resolve-domains` | Send the domain for resolution by the VMess server. |
| `resolve-domains-and-accept-dns-returned-order` | Use the first usable local DNS answer. |
| `resolve-domains-and-prefer-ipv4` | Prefer IPv4, falling back to IPv6. |
| `resolve-domains-and-prefer-ipv6` | Prefer IPv6, falling back to IPv4. |
| `resolve-domains-and-use-only-ipv4` | Require an IPv4 answer. |
| `resolve-domains-and-use-only-ipv6` | Require an IPv6 answer. |
| `resolve-domains-with-core-settings` | Use the core DNS settings and address preference. |

Local resolution uses an owned DomainResolver before VmessClient. Its preparation
hook applies the final target before DNS; it handles pending input while resolving.
Literal IPs are unchanged. The client snapshots the selected destination before
downstream transport nodes can replace the line destination with the server endpoint.

## Security and framing

All modes use authenticated AEAD request and response headers. `none` and `zero`
leave application bodies unencrypted and unauthenticated. TLS remains separately
configured. Select `zero` manually for TCP over TLS, or framed `none` for UDP,
when TLS should provide body protection. The client never infers TLS or downgrades
body security from its neighbors.

`auto` resolves once during node construction. It selects AES-GCM when runtime
CPU/OS capabilities prove AES and carryless multiplication acceleration and the
VMess OpenSSL provider supports AES; otherwise it prefers available ChaCha20-Poly1305.
An unavailable explicit cipher fails construction. Auto never selects `none`/`zero`.

| Security and command | Masking | Global padding | Authenticated lengths |
| --- | --- | --- | --- |
| AES-GCM or ChaCha, TCP/UDP | Optional | Optional; requires masking | Optional |
| `none`, TCP | Optional | Disabled | Disabled |
| `none`, UDP | Optional | Optional; requires masking | Disabled |
| `zero`, TCP | Disabled | Disabled | Disabled |

`none` uses chunk framing; `zero` represents unframed NONE and supports TCP only.
Authenticated lengths replace ordinary/masked lengths and do not require masking.
With authenticated lengths and global padding, SHAKE advances for padding rather
than a length mask. Request-header padding is an independent random 0..15 bytes.

For the internal bits CHUNK=1, MASK=4, PADDING=8 and AUTH_LENGTH=16, the supported
combinations are `1,5,13,17,21,29` for encrypted modes, `1,5` for TCP NONE,
`1,5,13` for UDP NONE, and `0` for zero. These are not a JSON bitmask setting.

## Request timing and response handling

Init prepares the destination and starts the transport without emitting a VMess
request. The first eligible payload sends immediately, including before Est,
during an Est callback or after advisory Pause. Fresh timestamp, request key/IV,
response marker, AuthID randomness, nonce and padding are generated when the first
request is committed. The request and first encoded body record share one ordinary
buffer. Larger TCP input is split in order into records of at most 16 KiB.

Every direct TCP Est is forwarded promptly, including repeats. UDP carrier Est maps
to the application once. The first Est starts the original idle deadline if no
request has been sent; repeats never reset it. On expiry, TCP emits one header-only
request even during advisory Pause. An idle UDP carrier defers that emission while
the exact carrier is paused and emits on Resume. An eligible payload still sends
immediately. Empty TCP input does not start a request. One ordinary output does not
promise one syscall, TCP packet or TLS record.

Outbound input never waits for a VMess response. There is no separate response-wait
deadline: VmessServer can legitimately wait for backend response data before sending
its response header. Existing transport lifecycle and timeouts remain applicable.
The client authenticates a bounded variable response, checks its expected marker
and exact outer command length, and consumes optional options/commands without
applying SwitchAccount, endpoint or credential changes. Coalesced body bytes remain
in order. Bad tags, malformed lengths and incorrect authenticated markers close
the affected connection.

## UDP, bounds and lifecycle

The application UDP line is borrowed. VmessClient creates and owns one same-worker
TCP carrier per association and preserves one fixed final target. Each accepted
datagram becomes one record; every complete nonempty received record becomes one
datagram. Native UDP drops empty local datagrams; every mode drops datagrams above
its maximum without splitting or starting a request. The idle timer can still emit
a header. An empty framed record means termination, after tag verification where
applicable.

| Body profile | Maximum local UDP payload |
| --- | --- |
| AES/ChaCha, ordinary/masked length | 65,519 bytes |
| AES/ChaCha, ordinary/masked length and padding | 65,456 bytes |
| AES/ChaCha, authenticated length | 65,535 bytes |
| AES/ChaCha, authenticated length and padding | 65,472 bytes |
| NONE, ordinary/masked length | 65,535 bytes |
| NONE, masked length and padding | 65,472 bytes |

With `packet-encoding=packetaddr`, command 2 targets the exact magic destination
`sp.packet-addr.v2fly.arpa:0`; that marker is never passed to DNS or a connector.
Each record contains a family/IP/port envelope followed by one application datagram.
The client retains one fixed target and carrier. Reply source IP/port must match
that target; unexpected sources are dropped and counted. Malformed envelopes close
the association. Header-only envelopes preserve empty application datagrams, while
an empty outer VMess record remains EOF. Subtract 7 bytes for IPv4 or 19 for IPv6
from the table above for the maximum packetaddr application payload.

Packetaddr requires an IP target. Explicit local DNS can resolve a domain first;
with `do-not-resolve-domains`, the association is refused before transport Init.
Fixed TCP with packetaddr fails construction; dynamic TCP keeps ordinary encoding.
This envelope is independent of Mux.Cool and XUDP and adds no carrier pooling.

Each direction has inclusive retained-input bounds of 2 MiB logical bytes,
1,024 entries and 8 MiB charged allocation, including active popped buffers and
incomplete fragments. These protect admission/storage; they are not a rate limiter
or a total-process RSS limit. TX and RX have independent reentry guards. Complete
admitted records drain incrementally and in FIFO order even if delivery causes
advisory Pause; there is no decoded-output queue solely for pressure.

VmessServer retains its 64 KiB unauthenticated-input limit. A sufficiently large
early plaintext burst can exceed that wire limit after framing while identification
is pending. The client does not treat the response as an authentication acknowledgement,
pace implicitly, enlarge the server allowance or reconnect/replay a refused burst.

The default `encrypted-counter-policy=wrap` uses every data ordinal 0..65,535
and continues from 65,535 to 0 under the same session keys. This intentionally
repeats the 16-bit AEAD nonce sequence for mainstream interoperability: it is not
rekeying and does not preserve AEAD nonce uniqueness. Authenticated lengths use the
same ordinal; SHAKE masking/padding continues without reset.

`strict` keeps outgoing data at 0..65,534 and reserves 65,535 for EOF. Valid incoming
data at 65,535 is delivered, then the association closes before nonce reuse.
NONE/zero accept this setting without an encrypted-counter effect. Counter policy
is local and adds no negotiation; a strict endpoint can close a wrap peer at its limit.

Finish follows WaterWall's full-close semantics: close the sender's side immediately,
cancel the first-payload timer, detach associations, settle retained buffers and wipe
session keys. A bounded termination may be sent only toward an open wire side after
a request has started when `send-termination=true`; false omits that record and
retains the same full-close lifecycle, including on strict exhaustion. Incoming
valid EOF is always accepted. Raw zero has no explicit framed EOF. These are local
choices with no handshake negotiation. Finish never creates a fresh request. Owned carrier Finish
returns with that carrier logically dead. Source-owner drain closes borrowed lines
and their dependent carriers before chain/pool teardown; quiescence prevents new
timer output or associations. The node remains active for the whole connection,
including `none`/`zero`.

## Read-only stats

The registered node API operation `stats` accepts an empty JSON object `{}` of at
most 64 bytes including whitespace. It has no reset or mutation operation. Access
requires the ordinary APIServer node/operation permission; see the shared
[node-operation contracts](../../WaterWall-Docs/docs/05-devguides/api/node-operations.mdx) in the node reference.

The fixed JSON response includes effective security/options/protocol, counter,
termination and packet encoding settings, approximate active application/carrier
counts, successful TX/RX body records, application bytes, wire bytes, wrap counts,
fixed close/drop reasons and suppressed verbose messages. Every uint64 counter is
a decimal JSON string, preserving full precision. Application bytes exclude
packetaddr envelopes and count successfully encoded TX data and delivered RX data;
wire bytes count submitted TX/received RX bytes including handshake and framing.
Framed EOF contributes a record but no application bytes. Snapshots load atomic
counters independently and are approximate while traffic continues; they never
traverse live lines. The client owns no destination backend, auth cache or replay
table. Invalid/nonempty bodies, expired deadlines and insufficient result/working
budgets return an API error. Working memory includes 4,608 bytes of fixed render/
metadata scratch plus the actual result-pool allocation charge.

## Build and metadata

`INCLUDE_VMESS_CLIENT` enables the node in standard builds. VmessClient and VmessServer
share the internal VmessCommon codec and its direct OpenSSL provider requirement
(3.3 or newer for streaming SHAKE), independently of the generic crypto backend.
Client-only builds need neither VmessServer nor AuthenticationClient/UserController.

The node is an L4 middle node with previous and next support,
`required_padding_left=0` and `kNodeFlagBlocksSplice`. The complete expanded chain
uses ordinary buffers; new output retains full onward pool padding.

Unsupported features include legacy headers, AlterID, AES-CFB, AES-CTR, Mux.Cool, XUDP,
reverse commands, automatic account/security switching, reconnect/replay and new
transport implementations.

WaterWall Mux framing is custom and does not provide external VMess Mux.Cool interoperability.
