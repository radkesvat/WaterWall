<!--
Documentation version: 2
Sync note: Keep this file, WaterWall-Docs/docs/02-noderefs/VmessServer.mdx and WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/VmessServer.mdx synchronized.
-->

# VmessServer Node

`VmessServer` accepts VMess AEAD requests, authenticates a UUID-backed account,
decodes TCP, fixed-destination UDP or packetaddr UDP traffic, and forwards it to `next`.
It implements the server protocol independently of its transport. Put `TlsServer`
or `HttpServer` before it when TLS or WebSocket transport is wanted.

## Authentication

Choose one authentication mode:

- Local users: configure `uuid`/`id`/`user-id`, `uuids`, or `users`/`clients`. A user object
  has a `uuid` (or `id`/`user-id`) and an optional `username`. Local users authenticate
  without an AuthenticationClient database.
- Managed users: configure `auth-client-node-name` and omit local credentials.
  Store the UUID string in the AuthenticationServer user's `password` field.
  The node uses AuthenticationClient's synchronized in-memory users and inserts
  its own `UserController` before the configured outbound node. Do not insert
  another UserController manually on that next edge.

Local credentials accept strict dashed/compact hexadecimal UUIDs or an exact nonempty
UTF-8 ID of at most 30 bytes. Short IDs use Xray's UUIDv5 mapping with the nil
namespace: `waterwall` maps to `106b9dde-356b-5769-b2f6-7ea4193ec5f7`.
Byte length matters; strings are not trimmed, folded or Unicode-normalized.
Equivalent normalized UUIDs are duplicate accounts and reject construction.
Managed passwords must contain the canonical mapped UUID; AuthenticationClient's
shared indexes do not normalize short IDs privately for VMess.

Managed mode inherits account admission, traffic accounting, connection/IP limits,
quotas and configured user shaping from the existing authentication system.
After an initial valid synchronization, ordinary control-network outages use the
last accepted user table; an unavailable initial table or explicitly rejected
AuthenticationClient blocks new managed admission. Administrative edits take
effect after the client receives a valid refresh. Local cached limits are not
global reservations across disconnected AuthenticationClients.

VMess transmits an encrypted AuthID rather than a plaintext UUID. Identifying a
new AuthID requires a worst-case `O(N)` search through `N` UUID candidate keys.
Derived command and AuthID keys are precomputed in a credential table shared by
the node's workers. Candidates include UUID-bearing accounts before admission
checks; a matching key alone does not authorize an inactive account. After a
cryptographic match, managed mode uses AuthenticationClient's indexed lookup to
revalidate the current account identity and admission state.

Authentication work is divided into bounded event-loop turns, and retained
pending work and credential caches have finite budgets. Cached keys do not
authorize a removed or replaced account. These limits bound work and storage;
they do not impose an application throughput rate.

## Protocol support

| Client body security | TCP | UDP |
| --- | --- | --- |
| `aes-128-gcm` | Supported | Supported |
| `chacha20-poly1305` | Supported | Supported |
| `none` with chunk framing | Supported | Supported |
| `zero` (unframed `none`) | Supported | Rejected |

All modes use authenticated AEAD request/response headers and `alterId: 0`.
`none` and `zero` do not encrypt or authenticate application bodies. Choose an
appropriate enclosing transport when body confidentiality is required.
`zero` is a client setting represented on the wire by `none` without chunking;
an unframed byte stream cannot preserve UDP datagram boundaries.

IPv4, IPv6 and nonempty domain destinations are supported by native requests.
Native UDP associates one backend with the request's fixed destination; its empty
framed record is a termination marker and local empty UDP replies are dropped.
`packetaddr` accepts the exact authenticated UDP marker `sp.packet-addr.v2fly.arpa`
with outer port zero. It never sends that marker to DNS or a connector. Each
record contains an IP/port envelope (7 bytes for IPv4, 19 for IPv6) and one
application datagram; domains and destination port zero are rejected. A header-only
envelope preserves an empty datagram. Each destination has one same-worker backend,
up to `packetaddr-max-destinations`; new-destination datagrams at capacity are dropped
while existing destinations continue. Backend Finish removes its entry immediately,
so later input may recreate it. Carrier close and shutdown drain every owned backend.
Queued replies retain independent encoded bytes and the original immutable source target.
Decoded application bytes pass through the managed UserController exactly once.

The maximum application body is 65,535 bytes plus 16 for authenticated-length
framing, minus the 16-byte encrypted-body tag when applicable and a 63-byte
global-padding allowance when enabled. Packetaddr subtracts its exact 7/19-byte
envelope again. Datagram payloads are never split; oversized
replies are dropped. These codec bounds do not enlarge an underlying UDP/IP limit.

Each encrypted direction has a 16-bit counter starting at zero.
`encrypted-counter-policy: "wrap"` is the default: nonempty records use all
ordinals `0..65535`, then continue at zero without resetting keys, IVs or SHAKE.
**Wrap repeats AEAD nonces under the same session key. It is not rekeying and does
not preserve nonce uniqueness.** It matches mainstream continuation behavior.
With `strict`, outgoing nonempty data uses `0..65534` and reserves `65535` for EOF;
incoming valid data at `65535` is delivered and then the association closes before
reuse. Body and authenticated-length records use the same ordinal, including
across wrap. NONE/zero bodies have no encrypted counter limit.

`send-termination: false` omits the optional outgoing empty framed record and uses
the existing full-close path. Incoming EOF remains accepted and encrypted EOF is
authenticated first. Idle Finish never emits a request; raw zero has no framed EOF.
Counter policy, accepted-security policy and termination are local settings, with
no new negotiation bit. A strict endpoint may close a wrapping peer at its limit.

`allowed-security` classifies actual body modes after authenticated request parsing
and before protected Init or backend creation. Denied authenticated modes never
reach fallback. `auto` is a client-local choice and is not a wire mode accepted in
this list. Operators choose `zero` for TCP with TLS or framed `none` for UDP with TLS
when they want the enclosing transport to provide body protection. VMess never
inspects TLS or automatically changes body security.

Legacy VMess headers/alter IDs, AES-CFB, Mux.Cool, XUDP and reverse commands are
unsupported. WaterWall Mux framing is not Mux.Cool-compatible and does not supply
external VMess multiplexing interoperability. AES-CTR is also excluded. TLS, WebSocket and HTTP handling belong to their existing nodes;
VmessServer does not inspect or configure those transports. It disables splice
for its chain because parsing and cryptography require ordinary memory buffers.

## Placement and examples

```text
TcpListener -> VmessServer -> TcpUdpConnector
TcpListener -> TlsServer -> VmessServer -> TcpUdpConnector
TcpListener -> HttpServer (WebSocket) -> VmessServer -> TcpUdpConnector
TcpListener -> TlsServer -> HttpServer (WebSocket) -> VmessServer -> TcpUdpConnector
```

A local-user node:

```json
{
  "name": "vmess",
  "type": "VmessServer",
  "settings": {
    "users": [
      {"username": "alice", "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5"}
    ],
    "connect": true,
    "udp": true
  },
  "next": "outbound"
}
```

A managed-user node:

```json
{
  "name": "vmess",
  "type": "VmessServer",
  "settings": {"auth-client-node-name": "auth-client"},
  "next": "outbound"
}
```

The outbound connector normally uses `"address": "dest_context->address"` and
`"port": "dest_context->port"`. Use `TcpConnector` for TCP-only configurations,
`UdpConnector` for UDP-only configurations, or `TcpUdpConnector` for both.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `uuid` / `id` / `user-id` | None | One local UUID or short ID; select one alias. |
| `uuids` | None | Array of local UUID/short-ID strings or user objects. |
| `users` / `clients` | None | Array of local UUID/short-ID strings or user objects; use either spelling. |
| `auth-client-node-name` | None | AuthenticationClient dependency; excludes all local-user settings. |
| `connect` | `true` | Permit TCP requests. |
| `udp` | `true` | Permit framed UDP requests. At least one request command must be enabled. |
| `handshake-timeout-ms` | `10000` | Absolute request-handshake deadline; incoming bytes do not extend it. |
| `auth-max-pending` | `4096` | Maximum pending authentication jobs for this node. |
| `auth-pending-max-bytes` | `67108864` | Shared pending-authentication logical input-byte budget. |
| `auth-cache-max-bytes` | `67108864` | Credential/authentication-cache storage budget in bytes. |
| `replay-max-entries` | `262144` | Maximum live entries in each of the node's AuthID and session replay tables. |
| `fallback-node-name` | None | Optional branch for eligible unauthenticated traffic. |
| `fallback-intentional-delay-ms` | `7` | Delay before fallback replay; `0` disables the intentional delay. |
| `fallback-intentional-delay-jitter-ms` | `1` | Additional fallback delay jitter; ignored when delay is zero. |
| `encrypted-counter-policy` | `wrap` | `wrap` or `strict`, independently applied per encrypted direction. |
| `allowed-security` | All four modes | Nonempty unique array of `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero`. UDP-only with only zero fails construction. |
| `send-termination` | `true` | Send optional outgoing framed EOF toward an open wire side. |
| `packetaddr` | `true` | Accept authenticated packetaddr UDP; `udp: false` rejects every UDP form. |
| `packetaddr-max-destinations` | `64` | Integer `1..1024`; maximum live backends per packetaddr carrier. |
| `verbose` | `false` | Reason-coded diagnostics limited to one message per node per second, without credentials or destination labels. |

Authentication limits and the handshake timeout are integers in `1..2147483647`;
replay table geometry must also fit the host. Invalid
configuration rejects startup. New options reject wrong types, duplicate keys,
unknown values, embedded NUL, malformed UTF-8 and fractional/out-of-range limits.
Capacity exhaustion rejects the affected new
request; it never evicts an unexpired replay mark to make room.

Before authentication completes, one connection retains at most 65,536 logical
input bytes in 256 buffers. Input and response queues each have limits of
2 MiB logical bytes, 8 MiB retained-buffer allocation charge and 1,024 entries;
active popped buffers remain charged. These fixed limits complement the shared
authentication budgets. They are not an RSS or total-process memory limit.

## Fallback and replay protection

Add `fallback-node-name` to select an existing stream branch for unknown
credentials or unavailable authentication. The original inspected prefix and
remaining bytes are replayed exactly and in order. No rejected identity is
published to the fallback branch, and the internal UserController is bypassed.

Fallback is unavailable after VMess authentication is recognized. Replayed or
expired AuthIDs, duplicate sessions, invalid tags, malformed authenticated
headers, unsupported authenticated requests, resource refusals and handshake
timeouts close the affected connection. They never become fallback traffic.

Replay tables are shared by all workers using this node. AuthIDs are accepted
within an inclusive 120-second wall-clock window and retained through their
entire remaining validity interval, including future timestamps. A backward
clock adjustment cannot make an already-expired request acceptable again.
Session identity includes the UUID, request body key and IV; its replay interval
is three minutes. Separate VmessServer instances have separate replay domains.

## Read-only stats

The registered `stats` operation accepts only an empty JSON object, with at most
64 input bytes including JSON whitespace. It requires the ordinary APIServer
permission for this node and operation; the historical tunnel callback alone does
not expose it. The operation returns fixed-schema JSON, or a bounded error such as
`busy` when the auth/replay snapshot lock cannot be acquired immediately. Deadlines,
response-body limits and actual pooled output allocation are checked. Reserve
at least 4,608 working bytes plus the result buffer allocation charge.

The response includes effective `encrypted_counter_policy`, `allowed_security`,
`send_termination`, `packetaddr`, `packetaddr_max_destinations`, `connect`, `udp`,
`verbose` and `managed`; `approximate` is true. All counters are decimal strings
preserving full uint64 precision. `applications` counts authenticated logical
associations, `carriers` counts live borrowed input lines (including pending/fallback),
and `backends` counts live owned UDP destination lines. `tx_records`/`rx_records`,
`tx_application_bytes`/`rx_application_bytes`, `tx_wire_bytes`/`rx_wire_bytes`,
`wrap_events` and `strict_exhaustion` are cumulative. Application bytes are decoded
upload bytes offered to the protected chain and admitted reply payload bytes,
excluding packetaddr envelopes; wire bytes count submitted framed replies and
received input, including handshakes. Native empty/oversized drops do not add reply
application bytes. Records count successful framed/body-codec operations; raw zero
is an unframed byte stream. Snapshots are approximate across counters and workers.

`pending_auth`, `pending_auth_bytes`, `auth_cache_bytes`, `authid_marks` and
`session_marks` report current retained occupancy (expired marks may await normal
reclamation). The fixed `reasons` object reports normal close, authentication
mismatch/unavailable table/expired AuthID, replay-or-capacity refusal, malformed
header, body/length failure, denied command/security, timeout, retained admission,
UDP oversize, malformed packetaddr, destination capacity and strict exhaustion.
The body/length categories include parser/geometry failures, not only tag failures.
Terminal reasons are counted once per carrier; datagram drops are counted per drop.
No UUID, password, user identifier or destination labels appear in diagnostics/stats.
Stats reads use atomic publication and bounded try-lock snapshots, never foreign
worker line or destination-map traversal. It has no mutation/reset operation.

## Validation

The namespace suite uses pinned V2Ray 5.53.0, Xray 25.6.8 and sing-box 1.12.0 peers
in both endpoint directions, with explicit unsupported cells. Long stop-and-wait
cases force more than 65,536 records over one counted transport connection.
Native Debug/Release tests drive two real wraps, independent boundary checkpoints,
packetaddr ownership/bounds, strict policy, parser mutations, stats and replay.
See `tests/cases/vmess_interop/README.md` and the Developer Guide Part 6 for commands.
