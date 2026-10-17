<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/AuthenticationServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/AuthenticationServer.mdx, and all files must keep the same documentation version.
-->

# AuthenticationServer Node

`AuthenticationServer` is a logical chain-end node for user database management.

It does not open sockets or perform direct network I/O. Instead, it keeps a `users_t` database in memory, loads that
database from JSON on startup, periodically writes the current state back to disk, and answers framed logical requests
from `AuthenticationClient`.

## What It Does

- acts as the upstream end of a logical request/response chain
- loads users from `db-path` into an in-memory `users_t`
- falls back to `db-path.backup` if the primary JSON file cannot be loaded
- restores the primary atomically while retaining the recovery backup
- periodically saves the in-memory users database
- publishes the previous committed primary as recovery backup before atomically replacing the primary
- can write hourly, daily, or weekly normal backup snapshots for operator use
- buffers upstream bytes until a full outer request message is available
- supports multiple request frames inside one outer message
- dispatches request frames to internal modules by request type
- sends one downstream response message containing all response frames for the processed request message

Available modules are `Authenticate`, `ping`, `GetUserBySHA256Hex`, `GetUserBySHA256Base64`, `GetUserBySHA256`,
`GetUserBySHA224Hex`, `GetUserBySHA224Base64`, `GetUserBySHA224`, `GetUserByPassword`, `AddNewUser`, `UpdateUser`,
`UpdateUserTraficStatsDiff`, `GetAllUsers`, and `PushUserStats`.

## Typical Placement

`AuthenticationServer` is the last node in a logical authentication chain.

A typical authentication chain is:

```text
AuthenticationClient -> AuthenticationServer
```

It must not have a `next` node.

## Configuration Example

```json
{
  "name": "auth-db",
  "type": "AuthenticationServer",
    "settings": {
      "db-path": "users.json",
      "file-save-rate-ms": 10000,
      "normal-backups": "daily",
      "normal-backups-path": "backups/",
      "normal-backups-count-limit": 10,
      "session-idle-timeout-ms": 600000,
      "verbose": false,
      "auth-clients": [
        {
          "name": "edge-1",
          "secret": "long-random-secret",
          "allow-stats-push": true,
          "allow-user-pull": true,
          "allow-user-write": false,
          "session-idle-timeout-ms": 600000
        }
      ]
    }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"AuthenticationServer"`.

### `settings`

- `db-path` `(string)`
  Path to the users JSON database file.

- `file-save-rate-ms` `(positive integer)`
  Periodic save interval in milliseconds.

- `session-idle-timeout-ms` `(optional positive integer, default: 600000)`
  Default session inactivity timeout in milliseconds. `600000` is 10 minutes.

- `verbose` `(optional boolean, default: false)`
  Enables focused debug logs for authentication line lifecycle, request-message parsing, module dispatch, permission
  decisions, session permissions, and response queue/send flow. It does not log secrets, session tokens, passwords, or
  raw user JSON.

- `normal-backups` `(optional string: "hourly", "daily", or "weekly")`
  Enables write-only normal backup snapshots. This field must be specified together with `normal-backups-path`; specifying
  only one of the pair is rejected.

- `normal-backups-path` `(optional string)`
  Directory used for normal backup snapshots. Relative and absolute paths are accepted. The directory is created with
  `createDirIfNotExists()` when it does not already exist. This field must be specified together with `normal-backups`.

- `normal-backups-count-limit` `(optional positive integer, default: 10)`
  Maximum number of normal backup snapshot files to keep for the configured database and period mode. This field is only
  accepted when normal backups are enabled.

- `auth-clients` `(non-empty array)`
  AuthenticationClient credentials and permissions. Each entry must contain non-empty `name` and `secret` strings.
  `allow-stats-push`, `allow-user-pull`, and `allow-user-write` are optional booleans and default to `false`.
  `session-idle-timeout-ms` is optional per client and defaults to the top-level session timeout.

## Database Format

The database is parsed and exported through the existing Waterwall user helpers:

- `ww/objects/users.h`
- `ww/objects/user.h`

The recommended on-disk shape is an object with a `users` array:

```json
{
  "users": [
    {
      "id": 1001,
      "name": "alice",
      "password": "alice:alice-secret",
      "email": "alice@example.com",
      "wireguard-allowed-ips": "10.44.0.23/32",
      "enabled": true,
      "limit": {
        "traffic": {
          "up": 1073741824,
          "down": 1073741824,
          "total": 2147483648
        },
        "bandwidth": {
          "up": 1048576,
          "down": 1048576
        },
        "ips": 4,
        "devices": 2,
        "connections-in": 16,
        "connections-out": 16
      },
      "time": {
        "created-at-ms": 1735689600000,
        "expire-at-ms": 1767225600000
      },
      "stats": {
        "traffic": {
          "up": 0,
          "down": 0
        },
        "connections-in": 0,
        "connections-out": 0
      }
    }
  ]
}
```

Saved databases are written as an object containing a `users` array.

Normal backup files are not used for startup recovery. They are historical snapshots written for the program user only;
the server still restores only from the existing `db-path.backup` recovery file.

### Accepted User Database Layouts

`usersFeedJson()` accepts these input layouts:

- `null`, an empty array, or an empty object
- an array of user objects: `[user, ...]`
- an object with a `users` array: `{"users": [user, ...]}`
- an object map: `{"alice": user, "bob": user}`
- one standalone user object containing `id` or `user-id`, plus `password` or `pass`

For object maps, the object key is used as a username hint only when the user object itself has no non-empty `name`.
The saver always rewrites the database in the normalized `{"users": [...]}` form.

In this example, `password` is still the authentication lookup key. The `id` is a separate durable user identity: keep it
unique and stable for that user so Waterwall can do safe, fast lookups and carry local runtime state across user-table
refreshes.

### User JSON Structure

A user object must contain a unique non-zero `id` and a password string. All other fields are optional:

- `id` or `user-id` `(required unsigned integer)`
  Durable logical user identity. Keep it unique across the users database and stable for the lifetime of that logical
  user. The password is still the authentication lookup key; `id` exists so Waterwall can resolve users safely and
  quickly across table refreshes, usage accounting, and runtime limit checks.

- `password` or `pass` `(required string)`
  Plaintext password used to create the user's password hash lookup keys.
  When a traffic-serving node such as `Socks5Server` authenticates a separate username and password pair, store the
  combined lookup string here. `Socks5Server` uses the literal form `username:password`, for example
  `"alice:alice-secret"`.

- `name` `(optional string)`
  Human-readable username. User names must be unique when non-empty.
  It is metadata for operators and is not used by forexample `Socks5Server` when checking SOCKS username/password credentials.

- `email` `(optional string)`
  User email metadata.

- `notes` `(optional string)`
  Free-form operator notes.

- `gid` or `group-id` `(optional unsigned integer)`
  Group identifier.

- `enabled` or `enable` `(optional boolean)`
  Defaults to `true`. Set to `false` to disable the user.

- `record-stat-interval-ms` `(optional non-negative integer)`
  Statistics record interval. If omitted, the default from `user.h` is used.

- `wireguard-allowed-ips` `(optional string)`
  One normalized WireGuard inner CIDR owned by this user, for example `"10.44.0.23/32"` or `"fd00::23/128"`.
  Empty, `null`, or omitted means the user has no WireGuard allowed IP configured. The field accepts IPv4 and IPv6, but
  it must contain exactly one CIDR, not a comma-separated list. Saved JSON normalizes the network address, so
  `"10.44.0.23/24"` is written back as `"10.44.0.0/24"`. Two users must not have overlapping WireGuard allowed ranges.

- `limit` `(optional object)`
  User limits. Missing fields mean no limit.

- `time` `(optional object)`
  User time metadata.

- `stats` `(optional object)`
  Runtime statistics. This is usually maintained by Waterwall, but can be supplied or updated when needed.

The numeric fields accept JSON numbers when they fit in JSON's safe integer range. Larger values may be written and
read as decimal strings.

### `limit` Object

`limit` can contain:

- `traffic`
  Object with `up`, `down`, and `total` byte limits. `u`/`d` are also accepted for `up`/`down`.

- `bandwidth`
  Object with `up` and `down` byte-per-second limits. `u`/`d` are also accepted.

- `ips` or `ip`
  Maximum IP count.

- `devices`
  Maximum device count.

- `connections-in` or `cons-in`
  Maximum inbound connection count.

- `connections-out` or `cons-out`
  Maximum outbound connection count.

Zero or missing limit values mean unlimited.

### `time` Object

`time` can contain:

- `created-at-ms` or `created_at_ms`
- `first-usage-at-ms` or `first_usage_at_ms`
- `expire-at-ms` or `expires-at-ms`
- `expire-after-first-usage-ms` or `expire-after-first-use-ms`

The same time fields are also accepted at the top level of the user object. Values are milliseconds since Unix epoch,
except `expire-after-first-usage-ms`, which is a duration after first usage.

### `stats` Object

`stats` can contain:

- `ips` or `ip`
- `devices`
- `connections-in` or `cons-in`
- `connections-out` or `cons-out`
- `speed`
  Object with `up`/`down` or `u`/`d`.
- `traffic`
  Object with `up`/`down` or `u`/`d`.

### User Database Concerns

- Passwords are stored in the JSON database as plaintext because `userToJson()` exports the `password` field. Protect
  `db-path` and `db-path.backup` with filesystem permissions appropriate for secret material.
- For `Socks5Server`, the stored password is the final authentication lookup key in `username:password` form, not just the
  password part submitted by the SOCKS client.
- Password-derived lookup keys are not stored directly in JSON. They are rebuilt from `password` while loading users.
- The SHA-256 password hash is the canonical password lookup key. SHA-224 is also indexed for explicit SHA-224 lookups.
  UUID credentials and WireGuard-style public keys are derived from the same password when applicable. Two users must not
  share the same password/SHA-224, SHA-256, UUID credential, or derived WireGuard public key.
- `wireguard-allowed-ips` is durable user configuration, not a password-derived key. It is stored in JSON, synchronized
  by `GetAllUsers`, and validated so configured ranges do not overlap between users.
- `id` is the durable logical user identity. Keep each non-zero id unique and stable for that logical user's lifetime;
  reusing an existing id for a different user can intentionally transfer client-side runtime state on the next
  `GetAllUsers` refresh.
- AuthenticationClient credentials are not stored in the user database. They live only in `settings.auth-clients`.
- The authoritative in-memory table tracks separate configuration and statistics revisions. These revisions are server
  metadata, not fields inside individual user objects.
- `AddNewUser` rejects duplicate usernames, duplicate durable user ids, duplicate password-derived lookup keys, and
  overlapping `wireguard-allowed-ips`, then saves the file immediately and bumps the configuration revision.
- `UpdateUser` uses the supplied password only to find the existing user and deliberately does not change password or
  password hashes. It updates in-memory metadata only, bumps the configuration revision, and does not force an immediate
  file save.
- `UpdateUserTraficStatsDiff` uses the supplied password only to find the existing user, then adds only
  `stats.traffic.up/down` as a delta. It bumps the statistics revision when traffic changes and does not force an
  immediate file save.
- Startup loading validates lookup-table consistency. A corrupted primary file can be recovered from `db-path.backup`,
  but an invalid backup cannot be repaired automatically.
- Avoid editing both primary and backup files by hand while Waterwall is running. The periodic saver may overwrite
  manual edits with the current in-memory database state.

## Save Behavior

Under the server state write lock, saving stages the proposed database in the primary directory, stages the
previous committed primary as `db-path.backup`, publishes that backup, then atomically replaces `db-path`.
Primary replacement is the commit point. Failure before it rejects `AddNewUser` and rolls its in-memory addition back;
the recovery backup never receives that rejected proposal. History/pruning or directory-sync failures after replacement
are logged and do not turn a committed addition into a rejected operation.

All primary, recovery, history and staging outputs are private before their first secret byte: exclusive `0600`
creation on POSIX and a protected Windows DACL granting the process user and SYSTEM access. Existing primary/recovery
permissions are restricted when loading; permission failure rejects startup. Writes, flush, file sync and close are
checked. Staging names are unique and are never startup recovery candidates. Cleanup removes only this operation's
staging files. This is not a guarantee of recovery from arbitrary filesystem or power-loss failures.

## Startup Recovery

A valid primary is authoritative. If primary loading fails, the server validates `db-path.backup` and restores it
through the same private atomic writer. The backup remains available throughout and after restoration. Historical
snapshots are separate and are never automatic recovery candidates. If neither primary nor recovery backup is valid,
node creation fails. A pre-existing backup has no provenance metadata proving when its contents committed.

## Logic Explanation

The server owns one authoritative table and store-level `config_revision` / `stats_revision` counters, initially 1.
Configuration mutations bump the former; new usage batches and first-use stamps bump the latter. Independent point
reads share the state read lock. Authentication, full pulls, saves and mutations hold its write lock.

### Control Identity And Sessions

Configured `auth-clients` names must be unique. Independent client processes must use distinct names. Sessions hold
bearer tokens, permissions, idle time and an association with their authenticated configured identity. Idle expiry
(default 600000 ms, swept on worker 0 every 60000 ms) and replacement remove sessions but preserve the identity's
accounting checkpoint. A valid-token request refreshes activity, including permission-denied requests.

Initial `Authenticate` accepts `name` and `secret` in a zero-token envelope and creates an opaque accounting epoch.
Its Session response contains 128 bytes: a 64-byte token followed by a 64-byte epoch. Each is 32 OS-secure random
bytes encoded as lowercase hexadecimal. A reconnecting running client includes `epoch` in Authenticate to resume it.
A missing or superseded checkpoint returns `accounting-continuity-lost`; it is never silently initialized for a retry.
Fresh enrollment without an epoch replaces the checkpoint and invalidates previous sessions for that identity.
`Authenticate` inside an already authenticated envelope is rejected with `already-authenticated`.

### Usage Accounting

A client retains one immutable delta batch across connection loss. Pushes identify users by durable nonzero `id`,
independent of passwords. The payload has exactly this supported shape:

```json
{"epoch":"<64 hexadecimal bytes>","sequence":1,"users":[{"id":42,"up":10,"down":0}]}
```

`sequence` starts at 1 and advances without wrapping. Each batch has 1..4096 unique user IDs and both nonnegative
`up` and `down` deltas per entry; at least one direction must be nonzero. Integers are plain signed-64-bit-range
integer tokens or decimal strings through UINT64_MAX. Decimal/exponent number tokens are rejected by integer readers.
The authenticated configured identity supplies the checkpoint key; payload fields cannot choose another identity.

Under one state write lock, the server validates epoch and sequence and hashes the exact payload bytes with SHA-256.
An exact replay of the last sequence/digest is acknowledged before current-account validation. Exactly the next
sequence validates every entry before any mutation, applies saturating traffic and missing first-use timestamps, then
publishes its checkpoint. Older sequences, gaps, conflicting replay content, unknown IDs and duplicate IDs fail without
partial application. Only the current epoch's session may report. Checkpoint storage is constant per configured identity;
it contains no users-table snapshot or unbounded batch history.

The Ok ACK JSON contains `epoch`, `sequence`, a 64-character hexadecimal `digest`, and `needs-pull: true`.
The client validates all three batch identity fields, advances only the acknowledged subset's baseline, and pulls fresh
authoritative totals and first-use time. Pull installation preserves local post-snapshot traffic as `G + (A - B)`.
No full table is installed while a batch remains unresolved. Reconnect order is authenticate/resume, replay pending
batch, validate ACK, then pull. Blocked pull/push requests coalesce until this ordering permits them.

Epoch/checkpoint state is runtime-only. Accounting continuity across process crashes or restarts is not provided.
An unresolved batch whose continuity is lost stays identifiable and stops automatic synchronization for operator
reconciliation. With no uncertain batch, a client may enroll afresh and pull. The separate administrative
`UpdateUserTraficStatsDiff` operation remains a raw delta and is not retry-safe.

Traffic-serving nodes use AuthenticationClient handles and copy-out APIs; they never receive borrowed user pointers.
Credential eligibility checks enabled state, expiry and cumulative traffic. Live connection/IP admission remains local
to one client runtime; saved gauge values do not reserve or exhaust live capacity. The protocol has no encryption of
its own; remote chains require an authenticated protected transport.

## Request And Response Framing

Upstream payload bytes are buffered as a stream. The request envelope is:

- 4-byte unsigned big-endian body size
- 64-byte session token
- request payload bytes

The body size is the number of bytes after the size prefix, so it includes the 64-byte token plus the request payload.
For an unauthenticated `Authenticate` request, the token is ignored and may be all zero bytes. Every other request
requires a valid session token issued by `Authenticate`. If a message uses a valid session token, it must not contain an
`Authenticate` frame.

The request payload contains one or more request frames:

- 1-byte request type
- 4-byte (32-bit) correlation ID
- 4-byte unsigned big-endian request data length
- request data bytes

Each request frame is validated before dispatch. If the envelope body is too small for the token, the request payload is
empty, contains trailing bytes smaller than a request header, or declares request data that is not fully present inside
the request payload, `AuthenticationServer` logs a warning and closes the logical connection safely.

Each module returns a response frame:

- 1-byte response type
- 4-byte (32-bit) correlation ID copied from the request
- 4-byte unsigned big-endian response data length
- response data bytes

After all request frames in one message are processed, the server combines all response frames into a single response
payload and sends it with the response envelope:

- 4-byte unsigned big-endian body size
- 8-byte unsigned big-endian configuration revision
- 8-byte unsigned big-endian statistics revision
- response frame bytes

Both revisions start at `1` when the tunnel is created. Configuration-changing requests such as `AddNewUser` and
`UpdateUser` increment the configuration revision. Traffic-stat updates increment the statistics revision when they
actually apply a non-zero traffic delta.

This keeps the request/response transport extensible for additional request types.

## Modules

Modules live under `tunnels/AuthenticationServer/modules/`.

Request types:

- `1`: `ping`
- `2`: `GetUserBySHA256Hex`
- `3`: `GetUserBySHA256Base64`
- `4`: `GetUserBySHA256`
- `5`: `GetUserByPassword`
- `6`: `AddNewUser`
- `7`: `UpdateUser`
- `8`: `UpdateUserTraficStatsDiff`
- `9`: `GetAllUsers`
- `10`: `Authenticate`
- `11`: `PushUserStats`
- `12`: `GetUserBySHA224Hex`
- `13`: `GetUserBySHA224Base64`
- `14`: `GetUserBySHA224`

Response types:

- `0`: ok
- `1`: `pong`
- `2`: user
- `3`: users database
- `4`: session token
- `255`: error

`Authenticate` is public. Every other module requires a valid session token. User lookup and full-table pull modules
also require `allow-user-pull`; user create/update modules require `allow-user-write`; traffic-stat modules require
`allow-stats-push`.

### Authenticate Module

Request data is `{"name":"edge-1","secret":"long-random-secret"}` for fresh enrollment, or the same object
with `"epoch":"<64 hexadecimal bytes>"` for resumption. The outer token is zero. Success returns type `4` and
128 bytes: token then epoch, 64 hexadecimal bytes each. Later requests carry the token in their envelope.
Malformed credentials fail, authenticated-envelope enrollment returns `already-authenticated`, and failed resumption
returns `accounting-continuity-lost`.

### Ping Module

The `ping` module expects request data equal to `ping` and returns response data equal to `pong`. The response preserves
the original 4-byte (32-bit) correlation ID.

If ping receives other request data, it returns an error response frame with the same correlation ID.

### GetUserBySHA256Hex Module

The `GetUserBySHA256Hex` module expects request data containing exactly 64 hexadecimal characters, representing a
SHA-256 digest. Uppercase and lowercase hex are accepted.

If a user with that SHA-256 password digest exists, the module returns response type `2` and response data containing
the full serialized user JSON object.

If the hex input is malformed or no user matches the digest, it returns an error response frame with the same
correlation ID.

### GetUserBySHA256Base64 Module

The `GetUserBySHA256Base64` module expects request data containing a standard padded base64 string that decodes to a
32-byte SHA-256 digest. For a SHA-256 digest this is normally 44 base64 characters.

If a user with that SHA-256 password digest exists, the module returns response type `2` and response data containing
the full serialized user JSON object.

If the base64 input is malformed or no user matches the digest, it returns an error response frame with the same
correlation ID.

### GetUserBySHA256 Module

The `GetUserBySHA256` module expects request data containing exactly the raw 32 bytes of a SHA-256 digest.

If a user with that SHA-256 password digest exists, the module returns response type `2` and response data containing
the full serialized user JSON object.

If the raw digest size is wrong or no user matches the digest, it returns an error response frame with the same
correlation ID.

### GetUserBySHA224Hex Module

The `GetUserBySHA224Hex` module expects request data containing exactly 56 hexadecimal characters, representing a
SHA-224 digest. Uppercase and lowercase hex are accepted.

If a user with that SHA-224 password digest exists, the module returns response type `2` and response data containing
the full serialized user JSON object.

If the hex input is malformed or no user matches the digest, it returns an error response frame with the same
correlation ID.

### GetUserBySHA224Base64 Module

The `GetUserBySHA224Base64` module expects request data containing a standard padded base64 string that decodes to a
28-byte SHA-224 digest. For a SHA-224 digest this is normally 40 base64 characters.

If a user with that SHA-224 password digest exists, the module returns response type `2` and response data containing
the full serialized user JSON object.

If the base64 input is malformed or no user matches the digest, it returns an error response frame with the same
correlation ID.

### GetUserBySHA224 Module

The `GetUserBySHA224` module expects request data containing exactly the raw 28 bytes of a SHA-224 digest.

If a user with that SHA-224 password digest exists, the module returns response type `2` and response data containing
the full serialized user JSON object.

If the raw digest size is wrong or no user matches the digest, it returns an error response frame with the same
correlation ID.

### GetUserByPassword Module

The `GetUserByPassword` module expects request data containing the exact plaintext password lookup key without a trailing
NUL. The payload must be non-empty and must not contain embedded NUL bytes.

For `Socks5Server`, that lookup key is the SOCKS username, a literal `:`, and the SOCKS password. For example, SOCKS
credentials `alice` and `alice-secret` are looked up as `alice:alice-secret`.

If a user with that password exists, the module returns response type `2` and response data containing the full
serialized user JSON object.

If the password payload is malformed or no user matches the password, it returns an error response frame with the same
correlation ID.

### AddNewUser Module

The `AddNewUser` module expects request data containing a JSON object for one user, using the AuthenticationServer user
format described above. The submitted user must contain a non-zero unique `id`/`user-id`.

The module validates that the payload is parseable JSON, that it is a user object, that the user can be created, and
that the new user's id, name, and password hashes do not conflict with existing users. If validation passes, the user
is added to the in-memory database and the users file is saved immediately through the private atomic commit sequence.
If that immediate save fails, the module attempts to roll back the in-memory add and returns a save error.

On success it returns response type `0` and response data equal to `user-added`.

If validation or saving fails, it returns an error response frame with the same correlation ID. If the file save fails
after the in-memory add succeeds, the module attempts to remove that user from memory and returns
`database-save-failed`.

`storage-unavailable` reports rejected user storage/index capacity or failure to initialize the native locks for a
copied user. Heap exhaustion terminates the process instead of producing an error response.

### UpdateUser Module

The `UpdateUser` module expects request data containing a full user JSON object in the same format exported by
`userToJson()`. The password field is used only to find the existing user by its SHA-256 password hash; password and
password-hash values are not updated by this module because they are database lookup keys. The submitted `id`/`user-id`
must be present, non-zero, and match the existing user found by that password hash.

If the user exists, the module updates the mutable user fields in memory, including name, email, notes, group ID,
enabled state, limits, time information, stats, record-stat interval, and `wireguard-allowed-ips`. It does not trigger an
immediate database file save; the normal periodic save timer is still responsible for persisting in-memory state later.

On success it returns response type `0` and response data equal to `user-updated`.

If the JSON is malformed, the user does not exist, the submitted id is missing or mismatched, or the update would create
a conflicting user name or overlapping `wireguard-allowed-ips`, it returns an error response frame with the same
correlation ID.

`capacity-rejected` reports an unrepresentable index-capacity request; the rejected update is not applied.

### UpdateUserTraficStatsDiff Module

The `UpdateUserTraficStatsDiff` module expects request data containing a full user JSON object. The password field is
used only to find the existing user by its SHA-256 password hash. The submitted `id`/`user-id` must be present,
non-zero, and match the existing user found by that password hash.

If the user exists, the module reads `stats.traffic.up` and `stats.traffic.down` from the supplied JSON and adds those
values to the existing user's traffic counters. No other user fields are updated. The add operation uses the same
saturating counter behavior as `userAddTraffic()`. If a non-zero traffic delta is accepted and the authoritative user has
no `first-usage-at-ms` yet, the server stamps it with the current server time.

This operation does not trigger an immediate database file save; the normal periodic save timer is still responsible
for persisting in-memory state later.

On success it returns response type `0` and response data equal to `user-traffic-stats-updated`.

If the JSON is malformed, the user does not exist, or the submitted id is missing or mismatched, it returns an error
response frame with the same correlation ID.

### GetAllUsers Module

The `GetAllUsers` module expects an empty request payload.

On success it returns response type `3` and response data containing the normalized users database JSON from
`usersToJson()`, plus response-only server-time metadata:

```json
{"users":[...],"server-time-ms":1767225600000}
```

`server-time-ms` is not written to the database. `AuthenticationClient` uses it to project server-owned expiry fields onto
the client's local clock.

A pull returns authoritative counters and current envelope revisions without changing the accounting checkpoint.

If the request contains unexpected data, or if exporting/serializing the in-memory database fails, it returns an error
response frame with the same correlation ID.

### PushUserStats Module

The payload is the immutable `epoch` / `sequence` / `users` delta batch described above. The complete batch is
validated before mutation. Success returns type `0` and JSON identifying the accepted epoch, sequence and exact
payload digest, with `needs-pull: true`. Replaying the last identical batch returns the same accounting confirmation
without applying it again, even if an account has since changed or disappeared. Permission, epoch, sequence and
input failures return a correlated Error response.

## Lifecycle Behavior

On upstream `Init`, `AuthenticationServer` initializes its per-line buffer state and sends downstream `Est` toward the
previous tunnel.

On upstream payload, it buffers bytes, extracts every complete outer message, processes each contained request frame,
and sends one combined response message downstream with `tunnelPrevDownStreamPayload()`.

On upstream `Finish`, it destroys only its own per-line state. It does not call `lineDestroy()` because it did not
create the line.

If the server itself has to terminate a logical connection, such as for a malformed oversized frame, it destroys its
own line state first and then sends `tunnelPrevDownStreamFinish()`.

## Notes And Caveats

- The current outer message payload limit is 16 MiB.
- The current request data limit is 16 MiB.
- The current response payload limit is 16 MiB.
- Queued and active responses share 1024 entries, 16 MiB plus the 20-byte envelope in logical storage, and 32 MiB
  allocation charge. Refusal closes only that line and releases all retained storage.
- Responses drain in FIFO order through at most 16 KiB stream chunks, preserving chain padding and nested callback
  order. Pause gates endpoint output; active backing allocations remain charged until release.
- Temporary construction retains at most one bounded response frame, one growing message (each at most 16 MiB plus
  envelope), one bounded serialized JSON text (16 MiB plus five spare printer bytes), and one output chunk. Allocation
  replacement may briefly overlap old/new storage. JSON trees, account tables, pools and transport queues are separate;
  this budget is not a total-RSS bound.
- Incoming request storage has the 16 MiB payload plus 68-byte envelope bound, 1024 entries and 32 MiB charge;
  one extracted active request is separate bounded parsing scratch.
- This node does not require left padding and does not prepend in-place.
- This node is not a packet tunnel and does not use packet-line semantics.

## User Database Performance

- SHA-256 is the canonical plaintext-password lookup key. A password lookup
  derives SHA-256 once and resolves through the SHA-256 hash index; there is no
  fallback scan over the user table, so both hits and misses are average O(1).
  The exact plaintext comparison after an index hit is the authoritative,
  collision-safe check.
- All keyed lookups (SHA-224, SHA-256, UUID, WireGuard public key, durable id,
  non-empty name) are average O(1); WireGuard Allowed-IP address lookup and
  range-overlap detection are O(log M) through an ordered interval index.
- Accounting retains only the last sequence/digest per configured client; full pulls serialize the authoritative table.
- Pure point-read request messages (`Ping`, `GetUserBySHA-224/256`, and
  `GetUserByPassword`) share the server state read lock and may execute
  concurrently. Any message containing authentication, `GetAllUsers`, a user
  mutation, a stats mutation, or an unknown/mixed non-point-read request takes
  the state write lock for the full dispatch.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainEnd` &#124; `kNodeFlagNoChain` |
| `can_have_prev` | `true` |
| `can_have_next` | `false` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayerNone` |
| `required_padding_left` | `0` bytes |
