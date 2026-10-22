<!--
Documentation version: 161
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/AuthenticationClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/AuthenticationClient.mdx, and all files must keep the same documentation version.
-->

# AuthenticationClient

`AuthenticationClient` is the frontend side of the Waterwall authentication database protocol. It is a chain-head control
node: when the tunnel starts it creates one internal control `line_t` on worker 0, sends that line upstream to its next
node, authenticates with `AuthenticationServer`, pulls the authoritative users table, and periodically keeps the session
alive and pushes local traffic counters.

It is not a data pass-through tunnel. Other tunnels use its internal API from
`include/AuthenticationClient/interface.h` to read users or add traffic to the local table.

## Expected Chain

Local loopback client-side chain:

```text
AuthenticationClient -> TcpConnector
```

The connector path should reach an `AuthenticationServer`. The client sends protocol bytes upstream with
`tunnelNextUpStreamPayload()`. Responses come back through the normal downstream direction into
`AuthenticationClient`.

`AuthenticationClient` owns the control line it creates. Because it is the line creator, it is also the only tunnel that
destroys that line.

## Configuration Example

Minimal in-process authentication chain:

```json
{
  "name": "auth-client",
  "type": "AuthenticationClient",
  "settings": {
    "name": "edge-1",
    "secret": "long-random-secret"
  },
  "next": "auth-db"
}
```

Local loopback transport example:

```json
{
  "name": "auth-client",
  "type": "AuthenticationClient",
  "settings": {
    "name": "edge-1",
    "secret": "long-random-secret",
    "ping-interval-ms": 60000,
    "pull-interval-ms": 300000,
    "push-interval-ms": 300000,
    "reconnect-interval-ms": 5000,
    "request-timeout-ms": 120000,
    "max-pending-requests": 64,
  "sync-max-users": 100000,
  "sync-max-bytes": 268435456,
    "traffic-multiplier": 1,
    "verbose": false
  },
  "next": "auth-server-connector"
}
```

```json
{
  "name": "auth-server-connector",
  "type": "TcpConnector",
  "settings": {
    "address": "127.0.0.1",
    "port": 9000,
    "nodelay": true
  }
}
```

The authentication protocol carries the client credentials and the full user table, including user passwords.
Untrusted remote links require an authenticated encrypted transport with server identity verification. For example,
change the authentication node's `next` to `auth-tls`, and insert this supported TLS wrapper before the connector:

```json
{
  "name": "auth-tls",
  "type": "TlsClient",
  "settings": {"sni": "auth.example.com", "verify": true, "alpns": []},
  "next": "auth-server-connector"
}
```

Point the connector at that server's TLS listener. The server composition is
`TcpListener -> TlsServer -> AuthenticationServer`; `TlsServer` uses `cert-file` and `key-file` for a certificate valid
for `auth.example.com`. `verify:true` verifies the chain and hostname. The bare `127.0.0.1` example above is local.

Configured credentials must fit an Authenticate data payload of 16,375 bytes after JSON escaping, including a
64-byte resume epoch. Oversized values fail startup without truncation.

The `settings.name` and `settings.secret` pair must match one entry in the upstream `AuthenticationServer`
`settings.auth-clients` array:

```json
{
  "name": "edge-1",
  "secret": "long-random-secret",
  "allow-user-pull": true,
  "allow-stats-push": true,
  "allow-user-write": false
}
```

Traffic-serving nodes reference the client by node name. For example, `Socks5Server` uses the already configured
`AuthenticationClient` like this:

```json
{
  "name": "socks-server",
  "type": "Socks5Server",
  "settings": {
    "auth-client-node-name": "auth-client",
    "connect": true,
    "udp": false
  },
  "next": "outbound-tcp"
}
```

`AuthenticationClient` is not placed in the data path for `Socks5Server`. It runs its own control connection and exposes
the pulled users table through its internal API.

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node. Other nodes, such as `Socks5Server`, use this value when they reference the
  authentication client.

- `type` `(string)`
  Must be exactly `"AuthenticationClient"`.

- `next` `(string)`
  Required. The next node must lead to an `AuthenticationServer`, either directly or through transport/client tunnels
  such as `TcpConnector`, `TlsClient`, or other chain components.

### `settings`

- `name` `(string)`
  Authentication client name sent to `AuthenticationServer`. This is a control-plane credential name and must match one
  entry in the server's `settings.auth-clients` array.

- `secret` `(string)`
  Authentication client secret sent with `settings.name`. This is not a traffic user's password.

## Communication Model

`AuthenticationClient` uses one long-lived control line, not one line per request or per job.

On startup, worker 0 creates a single internal `line_t` and sends `Init` to the next tunnel. In a normal chain such as
`AuthenticationClient -> TcpConnector`, that one WaterWall line becomes one outbound transport connection to the
server-side chain. All authentication, ping, pull, and push requests are framed as protocol messages over that same line.

Separate operations do not open separate connections. Timer-driven sync, explicit `authenticationclientRequestPull()`,
explicit `authenticationclientRequestPush()`, and the initial authentication flow all enqueue request messages on the
same control line. Responses are matched to requests by `correlation_id`, so multiple replies can be recognized even when
more than one request is pending on the same transport.

The client keeps the control line open while the downstream transport stays alive. If that transport closes, downstream
`Finish` closes and destroys the owned control line, clears the active session token, clears pending request state, and
schedules reconnect. The next connection starts with a new `Authenticate` request; the old token is not reused by the
client, even though the server may keep the old session record until its idle timeout expires.

While disconnected or not yet authenticated, new protocol requests are not sent. The local users table remains available
to callers as a cache, but server synchronization resumes only after reconnect, transport `Est`, and successful
authentication.

## Settings Reference

Required settings:

```json
{
  "name": "edge-a",
  "secret": "shared-secret"
}
```

Optional settings:

```json
{
  "ping-interval-ms": 60000,
  "pull-interval-ms": 300000,
  "push-interval-ms": 300000,
  "reconnect-interval-ms": 5000,
  "request-timeout-ms": 120000,
  "max-pending-requests": 64,
  "sync-max-users": 100000,
  "sync-max-bytes": 268435456,
  "traffic-multiplier": 1,
  "verbose": false
}
```

All five interval settings accept plain JSON integers from `0` through `2147483647` (`INT_MAX`).
`max-pending-requests` accepts integers from `1` through `2147483647`.
Defaults apply only when a setting is absent. Present values with fractions, decimal or exponent spelling,
strings, `null`, or values outside the range are rejected at startup; they are never rounded or wrapped.
The existing meaning of an explicitly configured `0` is preserved for each interval.

`ping-interval-ms` sends authenticated `Ping` requests and also retries `Authenticate` while the transport is connected
but not authenticated.

`pull-interval-ms` enables periodic revision checks for `GetUsersPage`. A value of `0` disables timer-driven pulls, but
the client still completes a required refresh after successful authentication and every matching usage ACK, including replay ACKs.

`push-interval-ms` enables periodic `PushUserStats`. A value of `0` disables periodic pushes. Other tunnels can still
ask for a push through the internal API.

When pull or push is enabled, one `sync_timer` runs at the shortest enabled pull/push interval. Each sync tick checks
which jobs are due and attempts `PushUserStats` first. `GetUsersPage` starts a traversal when configuration revisions differ or the pull cadence is due.
Statistics revision differences follow the configured cadence because a paged snapshot samples mixed times.
Periodic ticks during a traversal join it. An explicit `authenticationclientRequestPull()` during a traversal instead
coalesces into one later traversal; installation preserves that explicit demand.

`reconnect-interval-ms` controls reconnect delay after the control transport closes. A value of `0` queues a retry for a later loop turn. Repeated retry requests preserve the first positive deadline.

`request-timeout-ms` closes and reconnects the control line if any request stays pending longer than the configured
time using an independent worker-0 deadline timer, even with ping/pull/push disabled. A value of `0` disables it.

`max-pending-requests` is a request-admission ceiling. A full table retains desired pulls, pushes and catch-up work
until a matching response frees capacity; it does not repeatedly build batches, warn or arm a short retry timer.
The response is semantically validated and enrollment/ACK/error processing finishes before queued work resumes.
Local send rollback schedules a deferred continuation; stale correlations release no capacity. With request timeout
and optional jobs disabled, an unanswered request may wait indefinitely without busy retry.

`verbose` enables focused debug logs for the control-line lifecycle, reconnect decisions, timer ticks, and
request/response correlation flow. It does not log secrets, session tokens, passwords, or raw users JSON.

## Local Per-User Bandwidth

UserController enforces each user's `limit.bandwidth.u` and `.d` as actual logical bytes per second, with zero unlimited.
All lines, controllers and workers referencing this AuthenticationClient share each user's independent directional budget.
Different clients and users are independent; no distributed allowance is implied. Queued bytes are charged only at onward
handoff, while first positive arrival starts first-use expiry even before forwarding. Runtime buckets and fair-turn tickets
migrate by durable user ID and remain outside JSON, snapshots and persistence. Multipliers affect quota only. Per user in one AuthenticationClient, queues permit 4 MiB logical bytes,
8 MiB allocation charge and 1024 buffers/tickets. Per AuthenticationClient the limits are 64 MiB, 128 MiB and 16384
buffers/tickets, with independently accounted byte/buffer and ticket registries. These are not cross-client budgets.

## Traffic Multiplier

`traffic-multiplier` is an optional JSON number inside `settings`, defaulting to `1`. It accepts values from
`0.001` through `1000` with up to three effective decimal places. For example, `2` charges 2 GB of quota for 1 GB
of measured traffic, `1.5` charges 1.5 GB, and `0.5` charges 0.5 GB. Zero, negative values, strings and unsupported
precision are rejected at startup. The value is fixed for the lifetime of this AuthenticationClient instance.

The same multiplier applies to upload and download for every user and protocol referencing this instance.
`UserController` and other traffic callers pass actual measured bytes to AuthenticationClient. The client converts each
new measurement to charged usage exactly once, before updating local quota counters and checking limits. This also
applies while offline. It never multiplies totals received from AuthenticationServer or already charged pending batches,
retries, acknowledgements and catch-up debt. AuthenticationServer aggregates the reported charged bytes unchanged.

Calculation uses integer arithmetic and a separate fractional remainder for each user and direction. Whole charged
bytes are added as they accumulate, so splitting a transfer into small payloads cannot change its charge. At `0.5`, two
one-byte uploads together charge one byte; a one-byte download keeps its own half-byte remainder. Remainders survive
ordinary refreshes and reconnects by durable user ID, including credential changes for the same ID. They are process-local,
excluded from database JSON and synchronization, and discarded when the user is removed or the client is destroyed.
There is no crash recovery. Checked saturation never wraps a large charge back to a smaller counter.

First-use expiry starts on the first positive measured traffic, even when a discounted charge has not yet accumulated a
whole byte. Login and zero-byte calls do not start it. Existing expiry and reservation rules are unchanged.

Account traffic totals, traffic limits, and unacknowledged byte totals in status use **charged quota bytes**, not physical
network bytes. A combined total from clients with different multipliers cannot reconstruct actual traffic. Bandwidth,
speed, connection/IP counts, and first-use timestamps are not multiplied. Use separate AuthenticationClient instances
with distinct producer identities when different traffic-serving chains need different rates.

## Wire Protocol

The protocol intentionally matches `AuthenticationServer`.

Request message:

```text
u32 body_len
u8[64] session_token
request_frame...
```

Request frame:

```text
u8 request_type
u32 correlation_id
u32 request_data_len
u8[request_data_len] request_data
```

Response message:

```text
u32 body_len
u64 config_revision
u64 stats_revision
response_frame...
```

Response frame:

```text
u8 response_type
u32 correlation_id
u32 response_data_len
u8[response_data_len] response_data
```

All integer fields on the wire are big-endian. The client sends one request frame per message. The parser accepts any
number of response frames in a response message and matches each frame by correlation id. The response revisions are
remembered as the latest server revisions and compared with the local users-table revisions before timer-driven pulls.

## Startup Flow

On `onStart`, the tunnel queues startup work to worker 0.

Worker 0 then:

1. Arms the periodic ping and sync timers.
2. Creates the owned control line.
3. Initializes this tunnel's per-line state before calling the next tunnel.
4. Sends `tunnelNextUpStreamInit()`.

When the next side establishes the transport and sends downstream `Est`, the client marks the control line connected and
sends `Authenticate` with a zero session token.

`Authenticate` accepts `name`, `secret`, and an optional `epoch` for resumption. A Session response contains 128 bytes:
a 64-byte token followed by a 64-byte accounting epoch, both hexadecimal OS-secure random values. The client stores
the token, resolves any retained batch first, then pulls with `GetUsersPage`. A stale response cannot replace an enrolled epoch.

## Paged Synchronization

`GetUsersPage` (request 9, response `Users`/3) transfers a complete configuration through bounded pages. Each ordinary
page targets 256 KiB including framing and contains at most 128 users. An exceptional first record may occupy one page
up to the hard response-envelope limit, after all metadata/framing overhead. An impossible record returns correlated
`user-too-large`; fields are never truncated. Full tables larger than 16 MiB can synchronize.

`sync-max-users` defaults to `100000`; `sync-max-bytes` defaults to `268435456`. Both settings require positive exact
JSON integers representable on the host. The byte charge sums the exact received JSON object spans for user records,
including internal whitespace, excluding page metadata, commas and brackets. Admission checks declared totals and page
charges before constructing additional users; the client never reserves the advertised total in advance. Limit failure
reports `sync_limit`, drops staging and retains the usable cache and all usage debt. These are traversal admission bounds,
not an exact RAM cap: active/baseline/staged tables, indexes, JSON and shaping queues consume additional memory.
Changing these limits requires ordinary configuration restart; restarting does not recover accounting state.

Initial request data is an object with `epoch`, exact decimal-string `sequence` and 64-lowercase-hex `digest` for the
last matching usage ACK. Enrollment uses sequence `"0"` and 64 zero digest digits. Continuations add `cursor` and decimal
`total`. A cursor has 64 lowercase hex digits: instance ID (32), configuration revision (16), next position (16).
It grants no permission. Every request rechecks the producer token, pull permission and live accounting checkpoint.

Each page contains `instance`, `config-revision`, `stats-revision`, `total`, `position`, `count`, `cursor`, `complete`,
`validated`, `epoch`, `sequence`, `digest`, `server-time-ms`, `accounting-time-ms` and credential-bearing `users`.
Every 64-bit numeric field is an exact decimal string. Positions are contiguous and each nonempty ordinary page advances.
The empty database produces one complete empty data page. After the last data page (`complete:true`, `validated:false`),
the client sends its terminal cursor/total with `validate:true`. The server checks the configuration/checkpoint again
under its state lock and returns `validated:true`, zero count and empty users. It retains no frozen full-table snapshot.

A configuration edit, including a same-value edit, makes continuation/final validation return `stale_cursor`. The client
discards staging and restarts from page one after backoff while serving its old cache. Traffic/first-use changes by
other producers do not invalidate the cursor. Statistics are sampled at different times: the installed stats revision
is the first page's conservative sample; latest observed remote revisions remain separate. Ordinary cadence governs
later statistics refreshes, preventing a mixed-time snapshot from creating an immediate refresh loop.
Frequent configuration edits can repeatedly restart traversal. A failed mandatory refresh defers new usage reports;
missing-account debt is retained and can prevent installation. Cached service continues under locally known limits,
but these policies do not provide crash recovery.

No table/generation changes before successful final validation. All fallible preparation completes before runtime
migration. Installation merges current local deltas, observations, multiplier carry, reservations, bandwidth queues and
tickets by durable ID, then publishes active and baseline together once. Each user's clock uses its own page's paired
server/accounting samples and local receipt time, installed after migration; later pages never reset elapsed age.
An unresolved batch replays before page one. The whole traversal, including gaps and final validation, blocks new batches;
first-use/push work remains latched. A page checkpoint contradiction blocks continuity rather than erasing debt.

Absolute `request-timeout-ms` applies separately to every page and final validation, including paused requests. A valid
complete traversal can take longer than that timeout overall. Disconnect, timeout, malformed/no-progress page, conflict
or limit refusal releases staging only. Quiescence settles callbacks/timers before releasing owned state.

Repeated failed synchronization uses a monotonic retry streak. The first ordinary retry retains `reconnect-interval-ms`,
including a force-queued zero delay. Repeated failures start at `max(reconnect-interval-ms,1000)` and double to
`max(base,60000)`, with additive jitter from zero through one quarter of that delay. The effective deadline also honors
the stats-refusal floor of 30 seconds (or a larger configured interval). Requests, Resume, timers and first use cannot
bypass it; independent retry wakeups work with optional intervals zero. Session, Pong and intermediate pages do not reset
the streak; complete installation does. Status exposes `sync_retry_streak`, `sync_retry_remaining_ms`,
`sync_retry_failure`, `traversal_active`, `sync_staged_users`, `sync_staged_bytes` and `sync_total_users` without secrets.

## Local Users Table

The client keeps one active local users table. It is protected by a tunnel-level `wrwlock_t`.

`GetUsersPage` replacement is atomic from the point of view of other tunnels:

1. Each page is imported into a private staged `users_t`; terminal validation must succeed before installation.
2. The fresh table is validated, including requiring every user to have a non-zero durable id and rejecting overlapping
   `wireguard-allowed-ips` ranges.
3. Local unsynced charged traffic deltas, per-direction fractional charge remainders and process-local runtime counters
   are carried forward by durable user id.
4. Local first-use evidence, elapsed age and reservations migrate by ID; fresh clock metadata recomputes each expiry component.
5. The active table pointer is swapped under the write side of the rwlock.
6. The generation counter is incremented.
7. The old table is destroyed after the swap.

Readers hold the read side of the same rwlock while copying JSON, copying stats, or updating traffic by user id. This
prevents a user pointer returned by `users_t` from becoming invalid during the operation.

The table is local cache plus local counter accumulation. The server remains the source of truth for full user config,
including optional `wireguard-allowed-ips`. The server stores canonical `first-usage-at-ms`; clients report their
immutable first-local-traffic observations through deduplicated batches. Local expiry never waits for that report.

## Cached Admission And Local Expiry

`authenticationclientCanAuthenticate()` separates account admission from control-session readiness. Before the first
valid table and clock pair, during stopping, after terminal continuity failure, or after an explicit correlated
Authenticate `authentication-failed` response, new admissions reject. A validated successful Session clears that
credential-rejection block; disconnects, malformed responses, timeouts and `authentication-required` do not clear it.
`GetState()` and `IsReady()` continue to describe the control session. Password, SHA224, SHA256, UUID, exported
WireGuard-key lookup and connection admission recheck availability under control-mutex then users-lock ordering.

After initial synchronization, the last valid RAM cache has no age timeout. New and existing connections continue
through ordinary outages/re-authentication, subject to cached enabled status, quotas, expiry and local connection/IP
reservations. A malformed refresh retains the old cache. Credential rejection blocks new admission while existing
streams keep accounting and cached enforcement. Every reused HTTP request is a new admission; an in-flight exchange
or CONNECT stream continues. Administrative changes arrive with the next valid refresh.

These limits are local knowledge: two disconnected clients each seeing 80 GB of a 100 GB quota may each consume
20 GB, producing 120 GB after reconciliation. Neither quotas nor connection/IP reservations become strict global limits.
Already-accounted usage remains acceptable after a server disablement or lower-limit edit.

Every users page requires canonical exact `server-time-ms` and positive `accounting-time-ms`. Missing/invalid metadata rejects
the refresh without client-wall-clock fallback. Absolute dates use server wall time. The server accounting clock starts
at `max(wall-ms, 1)` once, then advances by fresh server monotonic elapsed time, independently of later wall corrections.

On first nonzero measured local upload/download, even when the charge rounds to zero, accounting samples fresh
monotonic time inside the user write lock and records an explicit valid local origin (including zero) and a positive immutable accounting-clock estimate. Login, reservation,
zero-byte calls and refresh rebasing never start it. Observation, counters and expiry decision share user-then-stats
locks; a null notification output does not suppress evidence. The elapsed age survives ACK, reconnect, repeated pulls,
omitted canonical first-use fields and duration-zero policy. Earlier canonical observations can increase age.

A duration edit recomputes only relative expiry from retained age. A future imported origin remains future until reached
or superseded by earlier real use. Absolute expiry is projected separately; an unchanged date keeps the earlier old/new
deadline, while explicit date edits/clears recompute only that component. The earlier enabled component governs payload
checks and the UserController sweep, including offline. Checked, saturating arithmetic never turns expired-at-zero into
unlimited access. Generic copies/JSON exclude anchors, ages, report markers and reservations; migration uses durable ID,
including same-ID credential changes, and retains new authoritative policy/timestamps.

Cross-machine clock conversion is an estimate affected by transit/serialization delay and oscillator drift. Local
countdowns retain elapsed age. Runtime host-suspend semantics remain unchanged; Linux CLOCK_MONOTONIC excludes suspension.
All this state is RAM-only; no crash recovery, journal, outbox or guaranteed final delivery is provided.

## External Status API

APIServer exposes the registered read-only `status` operation on worker 0. Its request and response content type is
`application/json`, encoded as UTF-8. Send `{}` for basic status or `{"include_accounting":true}` for aggregate accounting.
Unknown or duplicate fields, non-Boolean options, malformed JSON and trailing input return a bounded operation error.

Basic status includes `traffic_multiplier` as the configured exact decimal JSON number, even without accounting sampling.
It separates `can_authenticate` and `blocking_reason` from transport `connected`/`authenticated` and
`sync_phase`. A valid cache can admit new traffic during an outage; explicit credential rejection can block admission
while `users_loaded` remains true. Blocking precedence is stopping, not started, continuity error, credential rejection,
unusable cache/clock, then none. Queue/in-flight flags, unresolved batch sequence/count/size, remaining request/retry
limits, applied/observed revisions and success/failure history are included. `retained_catchup_slots` counts storage slots,
including settled entries, and is not an owed-user count.

When captured usage or first-use observations await their next batch, `sync_phase` is `catchup_pending`.
Capture, required refresh and in-flight operations retain their more specific phases. An `idle` client may still have
local traffic waiting for its next periodic push.

Success ages track validated authorization, installed table/clock and committed matching usage ACK separately. They survive
reconnect. Unknown ages are `null`; monotonic zero is valid. The bounded latest failure uses a fixed code and operation,
never server error text. Historical failure does not imply a current admission block. ACK age describes server-memory
acceptance, not a durable disk save.

`accounting_state` is `not_requested`, `available` or `unavailable`. Only an available requested sample includes
`locally_unacknowledged_upload_bytes`, `locally_unacknowledged_download_bytes` (both in charged quota bytes), `usage_user_count`,
`first_use_observation_count`, `accounting_lower_bound`, `sampling_started_ms` and `sampling_finished_ms`. A lost ACK may mean
the server has already applied some locally unacknowledged usage. Every unsigned 64-bit value is a decimal JSON string.
No tokens, epoch, raw batches, account identifiers, names, passwords, hashes or IP lists are returned.

Accounting merges active-minus-baseline usage, retained catch-up debt and immutable pending batches by durable ID, taking
overlapping maxima instead of double-counting. Later traffic after the immutable batch is included; retained-only entries
remain represented. First-use counts use explicit unacknowledged observation state and retained obligations, rather than
assuming any batch timestamp is unacknowledged. Exhausted counters and aggregate overflow set `accounting_lower_bound`,
including when the represented amount is zero.

Sampling uses coherent per-user copies over the reported monotonic interval; traffic continues between samples. It pins
the tables, preflights temporary storage against the handler reservation and performs bounded linear scan/radix-merge
work with deadline checks. Insufficient allowance or elapsed deadline preserves basic status and returns accounting as
`unavailable`. Queries never modify counters, baselines, observations, batches, retry state or synchronization scheduling.

## Internal API

The internal Waterwall API is exposed through:

```c
#include "AuthenticationClient/interface.h"
```

This is intentionally separate from `api.c`, which is the external program API pattern used by all tunnels.

Other tunnels must not receive or cache raw `user_t *` pointers from `AuthenticationClient`. Instead they use
`user_handle_t` from `ww/objects/user_handle.h`, which contains:

```text
users_generation
user_id
```

The handle is a value identifier, not an owned object. `user_id` is copied from the synced user record and must be
non-zero for the handle to be valid. A full users-table replacement increments the generation, so generation-gated read
helpers may reject old handles. Callers can either look up a fresh handle or check with
`authenticationclientUserHandleIsLive()`. `authenticationclientGetUserBySHA224()`,
`authenticationclientGetUserBySHA256()`, `authenticationclientGetUserByUUID()`, and
`authenticationclientGetUserByWireGuardPublicKey()` are alternate lookup entry points; successful lookups still return
the normal id-backed handle.

The `WithResult` wrappers preserve detailed lookup failures; `WithProfile` copies optional identity strings coherently
with the resolved handle. Release profiles with `authenticationclientUserProfileClear()`. Boolean wrappers and all
credential-family lookups remain available. `UserObservePayload` starts first use without charging; `UserCommitDelivery`
charges exactly forwarded bytes after bandwidth admission. `UserBandwidthRegister/SetEligible/Cancel/Reserve/Release/Preview`
manage directional fair turns and retained costs. `UserAccountTraffic` provides immediate measured accounting for existing
callers. The older `UserAddTraffic` is generation-sensitive and may reject a handle after refresh; ongoing enforcement
and the current observation/delivery path resolve durable IDs. Getters/copy-outs, handles and explicit pull/push remain.

Available internal operations:

```c
authenticationclientGetState(t)
authenticationclientIsReady(t)
authenticationclientCanAuthenticate(t)
authenticationclientUsersGeneration(t)
authenticationclientGetUserByPassword(t, password, &handle)
authenticationclientGetUserBySHA224(t, sha224, &handle)
authenticationclientGetUserBySHA256(t, sha256, &handle)
authenticationclientGetUserByUUID(t, uuid, &handle)
authenticationclientGetUserByWireGuardPublicKey(t, publickey, &handle)
authenticationclientUserHandleIsLive(t, &handle)
authenticationclientUserToJson(t, &handle)
authenticationclientUsersToJson(t)
authenticationclientUserGetStats(t, &handle, &stats)
authenticationclientUserAddTraffic(t, &handle, upload, download)
authenticationclientUserTryAdmitConnection(t, &handle, &ip_key, now_ms)
authenticationclientUserReleaseConnection(t, &handle, &ip_key)
authenticationclientUserAccountTraffic(t, &handle, upload, download, now_ms)
authenticationclientUserShouldClose(t, &handle, now_ms)
authenticationclientRequestPull(t)
authenticationclientRequestPush(t)
```

`authenticationclientUserToJson()` and `authenticationclientUsersToJson()` return new `cJSON` objects owned by the
caller. Stats are copied into caller storage. Traffic updates are applied through the handle's durable id; the caller
never mutates a `user_t` directly. Both traffic helpers accept actual measured upload/download bytes; callers must not
pre-multiply them. Stats copy-outs contain charged usage.

The live enforcement helpers resolve handles by durable id instead of rejecting them solely because a `GetUsersPage`
refresh bumped the local users generation. A miss means the user disappeared from the refreshed table. The `now_ms`
argument for these helpers is in the client's local monotonic clock domain, because expiry has already been projected
onto that clock when the users table was installed.

`authenticationclientRequestPull()` and `authenticationclientRequestPush()` use the current control line. Foreign
callers queue work to worker 0. Desired jobs coalesce while disconnected, paused or blocked by another synchronization
operation. A pull cannot replace the baseline during an unresolved push, and a push cannot overtake an active pull.
After authentication or a usage ACK, the required full pull completes before the next new usage batch. A retained batch
is replayed before this pull after reconnect. Once the required pull completes, a waiting push takes precedence over
ordinary periodic or explicit pulls, so repeated pull requests cannot indefinitely delay usage reporting. If there is
no usage to push, an ordinary queued pull can proceed immediately.
Credential eligibility checks enabled state, expiry and traffic quota; saved connection, IP, device and speed gauges do
not block lookup. Live capacity is reserved separately by the atomic runtime admission helper.

## Stats Push

The client synchronizes already-charged traffic deltas and first-use accounting observations keyed by durable user ID:

```json
{"epoch":"<64 hexadecimal bytes>","sequence":1,"users":[{"id":42,"up":10,"down":0,"first-usage-at-ms":1792252800000}]}
```

It retains the exact payload and an owned snapshot of included IDs, counter totals and first-use observations for the tunnel lifetime until an ACK matches epoch, sequence
and SHA-256 digest. Send refusal, timeout, malformed replies and transport/session loss preserve both owners.
Retries use the same bytes with a fresh correlation ID and the current token. Batches contain at most 4096 entries;
only represented users/directions advance on ACK. Sequence numbers never wrap, and empty batches are not sent.
ID, sequence and first-use timestamp are nonzero. Both byte deltas may be zero for an unacknowledged observation,
including when counters saturate. ACK marks only included observations acknowledged; it retains their local origin
and elapsed age. Later positive reports still carry the same producer timestamp.
The root has exactly `epoch`, `sequence`, `users`; each entry has exactly `id`, `up`, `down`, `first-usage-at-ms`, all required. Unknown,
duplicate or nontraffic fields reject the request. Complete valid JSON/UTF-8, no raw/escaped NUL or trailing data,
and an eight-container depth bound are required within the existing authentication message budget.
Plain integer tokens through INT64_MAX and decimal strings through UINT64_MAX are exact; integer readers reject
fractional, decimal/exponent, negative, nonfinite and overflowing input.

If `A` is current local traffic, `B` its acknowledged baseline and `S` the batch snapshot, ACK advances `B` to `S`
for that subset. New traffic stays in `A`. A subsequent pull installs global counters `G + (A - B)` with baseline `G`.
Every ACK, including a duplicate, requires a full pull before the next new usage batch so server-owned first-use time
and other clients' usage arrive.
First-use work and blocked desired pushes/pulls remain pending until they can run.
First-use reporting also remains deferred while a required/in-flight pull blocks it; its global latch and per-user
request flags are preserved. Pull completion continues the remembered push without another packet. Paused writes
suspend progress wakeups; Resume explicitly continues the remembered work.

A correlated `stats-push-not-allowed` keeps cached admission under cached enabled/expiry/quota and local capacity rules.
It retains the exact unresolved batch, first-use evidence and all debt. Other nonterminal push errors, including
`invalid-usage-batch`, `usage-digest-failed` and unknown errors, also retain the batch without assuming whether it committed.
The client reconnects and reauthenticates after a monotonic cooldown of at least 30 seconds, or the configured reconnect
interval when larger. One due retry is scheduled even when every periodic interval and the reconnect interval are zero;
traffic, explicit requests and Resume cannot bypass it. A Session does not clear reporting refusal; only the retained
batch's matching ACK clears it. Status reports bounded `stats_push_denied` or `stats_push_rejected` failure classes and
the actual retry/debt state. Remote error diagnostics escape at most 128 input bytes and explicitly mark truncation.

Until the retained batch settles, no full pull may overtake it: the cache can remain stale as during a control outage,
and later local traffic accumulates separately. Recovery requires the same live server accounting epoch. Permissions
are startup settings; changing them and restarting does not promise recovery of a lost process-local checkpoint.
`authentication-required` follows ordinary reauthentication with the same batch. `usage-replay-conflict` and
`usage-sequence-invalid` remain terminal accounting inconsistencies and block new admission.

Complete refreshes use bounded pages and retain the accounting barrier through final validation; see Paged Synchronization.

Reconnect order is Authenticate/resume epoch, replay retained batch if present, validate ACK, then full pull.
After that refresh, the client captures owed relative deltas and observations, including traffic during recovery,
and automatically drains them in bounded batches with a required refresh after every ACK. This works with all optional
intervals zero. A nonzero worker-0 progress timer yields between catch-up steps and retries resource refusals; failure
to establish required scheduling requests orderly shutdown. Quiescence detaches the timer and does not rearm it.
The capture is finite under continuing traffic and survives aggregate counter rebasing from other producers.
Captured relative debt remains reportable even if a saturating rebase hides it in the visible counters. Post-cut
traffic follows normal push settings and the first-use trigger. Another disconnect retains both the immutable pending
batch and outstanding relative catch-up debt. After replay/refresh, recapture merges that debt with visible unacknowledged
deltas without counting their overlap twice. Only a matching ACK consumes the represented debt; neither disconnect nor
counter rebasing clears it. Final tunnel destruction releases this RAM state without guaranteeing delivery.
The server retains a bounded checkpoint per configured client beyond session expiry/replacement. Independent client
processes need different configured names. A lost/superseded epoch with an unresolved batch enters
`kAuthenticationClientStateContinuityError`, keeps the batch, closes the transport and stops automatic synchronization
until the operator resolves the accounting condition. No reconciliation/reset API is provided. With no uncertain batch, fresh enrollment and pull can resume. This guarantee covers
connection loss while both processes run; it does not provide accounting recovery across process crashes/restarts.
An ACK means acceptance in server memory, not a disk save. Periodic/final database saving does not persist accounting
checkpoints. Client restart may lose unreported usage; server restart may lose acknowledged usage since its last
successful save and loses retry checkpoints. Shutdown does not guarantee final usage delivery.

Cumulative traffic and the earliest accepted first-use timestamp belong to the server aggregate. Remote `UpdateUser` edits select a durable
ID and patch configuration only, preserving counters, creation/first-use metadata, credentials and runtime state.
Configuration patches require `allow-user-write`; traffic batches require `allow-stats-push`. These permissions are
independent. There is no remote usage-reset operation.

Active outbound connections and IP reservations are local runtime admission state, not global telemetry. Stored/imported
IP, device, connection and speed statistics are neither a reliable live global occupancy view nor admission input.
Future connection reporting needs per-producer snapshots, ordering and expiry; speed needs measurement windows and
freshness, with missing samples distinct from zero. Distinct-IP reporting needs identity sets, windows and deduplication
across producers. Devices need defined identity and collection. No such reporting or reset mechanism is implemented.

## Timers

All protocol timers live on worker 0, the same worker as the owned control line:

`ping_timer` sends `Ping` while authenticated and retries `Authenticate` while connected but unauthenticated.

`sync_timer` drives both user-table pull and stats push using the shortest enabled pull/push interval. Each tick checks
the independent pull/push cadence, queues `PushUserStats` first when due, then queues `GetUsersPage` when revisions
differ or the pull cadence is due. Periodic ticks join an active traversal; explicit pull requests retain one later traversal.

`reconnect_timer` preserves the first positive retry deadline, rechecking actual monotonic due time. Zero-delay
retries use queued work, never recursive opening from Finish. A mutex-protected latch is published before queue
submission; run or cancellation settles it once. Cancellation touches no worker-owned line, pool or timer.

`request_timer` tracks the earliest outstanding request independently of the optional jobs, publishing its deadline
before Payload so synchronous replies/Finish are safe. Matching replies settle only their own requests.

Timers are detached in `onWorkerQuiesce` for worker 0, before owner drain, because timer deletion must happen on the same
worker event loop that owns the timer.

## Lifecycle And Line Safety

The control line's `AuthenticationClient` line state contains the downstream response read stream and its parser reentry guard. It is initialized
before `tunnelNextUpStreamInit()` and destroyed before the client propagates an upstream finish or destroys the owned
line.

Downstream `Finish` means the next side closed the transport. The client:

1. Removes the active control-line pointer under the control mutex.
2. Clears session token, authenticated state, in-flight flags, and pending requests.
3. Destroys this tunnel's line state.
4. Destroys the owned line.
5. Preserves an unresolved usage batch and outstanding catch-up debt, then schedules reconnect unless stopping or in continuity error.

When the client itself closes the control line, such as during worker-0 shutdown or malformed response handling, it
destroys its local line state first, then sends `tunnelNextUpStreamFinish()`, then destroys the owned line. The outward Finish does not callback toward its sender.

Response payload parsing holds a temporary line reference. If a re-entrant callback closes the line, the parser stops and
returns without touching destroyed line state.

## Direction Ownership

The client sends all requests upstream:

```c
tunnelNextUpStreamInit()
tunnelNextUpStreamPayload()
tunnelNextUpStreamFinish()
```

It receives server responses from downstream callbacks:

```c
AuthenticationClient::DownStreamEst
AuthenticationClient::DownStreamPayload
AuthenticationClient::DownStreamPause
AuthenticationClient::DownStreamResume
AuthenticationClient::DownStreamFinish
```

Pause and resume are not reflected to a previous tunnel because `AuthenticationClient` is a chain head and has no
previous data producer. They only update whether new protocol requests may be sent immediately.

## Packet-Line Semantics

`AuthenticationClient` is not a packet tunnel. It does not use packet lines and does not call `lineDestroy()` on any line
except the normal control line that it created itself.

## User Database Performance

- Plaintext-password lookups derive SHA-256 once and resolve through the SHA-256
  hash index with no fallback scan, so hits and misses are average O(1). The
  candidate is then confirmed with an exact plaintext comparison, so a
  hypothetical SHA-256 collision fails closed.
- The local sync baseline is duplicated with the native `usersCopy()` deep copy
  rather than a JSON round trip. Only the received `GetUsersPage` network response
  still requires one JSON parse into the active table.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainHead` |
| `can_have_prev` | `false` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayerNone` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `0` bytes |

Complete response messages drain before incomplete-input limits are checked, so a delivery may contain several
messages. Incomplete input stays below one maximum wire message (16 MiB plus the 20-byte envelope), with at most
1024 entries and 32 MiB allocation charge after compaction. Nested deliveries share a byte allowance of one maximum
wire message plus 2 MiB, including the older unread suffix; fragmented storage is compacted before refusing it.
Empty deliveries are recycled. One extracted message and a compaction destination are bounded parsing scratch;
the current synchronous delivery, account tables and pool caches are outside the retained-input allowance.
