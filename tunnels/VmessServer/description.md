<!--
Documentation version: 1
Sync note: Keep this file, WaterWall-Docs/docs/02-noderefs/VmessServer.mdx and WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/VmessServer.mdx synchronized.
-->

# VmessServer Node

`VmessServer` accepts VMess AEAD requests, authenticates a UUID-backed account,
decodes TCP or fixed-destination UDP traffic, and forwards it to `next`.
It implements the server protocol independently of its transport. Put `TlsServer`
or `HttpServer` before it when TLS or WebSocket transport is wanted.

## Authentication

Choose one authentication mode:

- Local users: configure `uuid`/`id`, `uuids`, or `users`/`clients`. A user object
  has a `uuid` (or `id`/`user-id`) and an optional `username`. Local users authenticate
  without an AuthenticationClient database.
- Managed users: configure `auth-client-node-name` and omit local credentials.
  Store the UUID string in the AuthenticationServer user's `password` field.
  The node uses AuthenticationClient's synchronized in-memory users and inserts
  its own `UserController` before the configured outbound node. Do not insert
  another UserController manually on that next edge.

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

IPv4, IPv6 and nonempty domain destinations are supported. UDP associates one
backend with the request's fixed destination. An empty framed body is a protocol
termination marker, not an empty UDP datagram.

Each encrypted direction has a 16-bit counter starting at zero. Server-to-client
data uses counters `0..65,534`; counter `65,535` is reserved for an authenticated
termination record. Client-to-server data may use counter `65,535`; the server
delivers that record and then closes the connection. Authenticated-length
records use the same counter values and exhaustion limits. Counters never wrap,
so these limits apply to records, not bytes, and long encrypted transfers need
a fresh connection.

Legacy VMess headers/alter IDs, AES-CFB, Mux.Cool, XUDP and reverse commands are
unsupported. TLS, WebSocket and HTTP handling belong to their existing nodes;
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
| `uuid` / `id` | None | One local UUID; use either spelling, not both. |
| `uuids` | None | Array of local UUID strings or user objects. |
| `users` / `clients` | None | Array of local UUID strings or user objects; use either spelling. |
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
| `verbose` | `false` | Enable additional protocol diagnostics. |

Authentication limits and the handshake timeout are integers in `1..2147483647`;
replay table geometry must also fit the host. Invalid
configuration rejects startup. Capacity exhaustion rejects the affected new
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

## Validation

The namespace suite uses a pinned V2Ray 5.53.0 client for the body-security and
transport matrix, managed/local users, incorrect credentials, fallback byte
integrity and orderly shutdown. See `tests/cases/vmess_interop/README.md` for
reference provisioning and focused commands. Native tests cover protocol
boundaries and replay admission independently of network timing.
