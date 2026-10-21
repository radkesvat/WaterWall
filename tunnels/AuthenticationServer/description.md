<!--
Documentation version: 163
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
`GetUsersPage`, and `PushUserStats`.

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
  Enables focused debug logs for line lifecycle, module dispatch, permission refusals and response queue/send flow.
  It does not log secrets, session tokens, passwords or raw user JSON.

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
  Both peers reject credentials at startup unless the exact escaped JSON handshake, including a 64-byte resume epoch,
  fits 16,375 bytes. Credentials are never truncated.

`file-save-rate-ms`, both the server-wide and per-client `session-idle-timeout-ms`, and
`normal-backups-count-limit` accept plain JSON integers from `1` through `2147483647` (`INT_MAX`).
`file-save-rate-ms` is required. Optional defaults or the per-client inherited timeout apply only when the setting
is absent. Present zero, negative, fractional, decimal/exponent, string, `null`, or out-of-range values fail startup
before timers or backup retention use the value.

## Administrative Audit Log

Omitting `audit-log` disables this feature. To enable it, add this object inside
`settings`:

```json
"audit-log": {
  "path": "logs/auth-admin.jsonl",
  "max-file-size": 16777216,
  "max-files": 7
}
```

`path` is required and names the active file exactly; relative paths use the
process working directory. Create its parent directory before starting WaterWall.
`max-file-size` is an integer byte limit, default 16777216 (16 MiB), from 16384
through 1073741824. `max-files` defaults to 7 and accepts 2 through 32, including
the active file. Unknown keys, duplicate keys and incorrect types are rejected.
There is no severity/log-level setting: ordinary logger filtering does not filter
audit events.

Rotation happens before appending a complete record that would exceed the size
limit. Archives are `path.1` (newest) through `path.N-1`; the oldest is removed
when necessary. Existing complete files are appended, not truncated on startup.
A nonempty active file without a final newline is refused; inspect and repair it
before restarting. The active file, archives and persistent `path.lock` sidecar
belong to this one writer. Use a dedicated path, separate from databases, backups
and ordinary logs, in an operator-controlled directory. When normal backups are
enabled, an active audit filename matching `authenticationserver-*.json` is
reserved inside `normal-backups-path`; canonical directory aliases are also
rejected. A distinct filename such as `auth-admin.jsonl` may share that directory.
Do not remove the lock
sidecar or rename/rotate these files externally while the server runs. The writer
requires regular files without link aliases, applies private permissions and
excludes a second writer. On Unix files are owner-only (`0600`); Windows uses a
protected ACL for the process user and SYSTEM. Startup fails if enabled audit
logging cannot open or validate its files. Audit path validation preserves the
current `MAX_PATH` bound, including archive/lock suffixes and resolved parent
names; it reports unsupported lengths/basenames, failed parent resolution and
actual protected-file overlaps separately. A resolution failure refuses startup.

The node records successful and rejected `create-user`, `update-user` and
`change-user-password` attempts that reach their registered handlers. It also
records the producer protocol's `AddNewUser` and `UpdateUser` outcomes, including
permission refusals from an authenticated producer. Reads, authentication,
traffic batches and gateway rejections before target dispatch do not create
administrative audit records. Unauthenticated producer refusals consume no queue slots or dropped-event counts.
This is an account-administration trail, not a
complete access/security log.

Each UTF-8 JSON line contains these bounded, permitted fields:

| Field | Meaning |
| --- | --- |
| `timestamp_ms` | UTC Unix wall-clock milliseconds as a decimal string; clock adjustments can move it backward. |
| `server_instance`, `sequence` | Process-local server identity and accepted-record order; sequence is a decimal string. Use these to distinguish restarts and ordering. |
| `config`, `node` | Logical target configuration and node names. |
| `source`, `actor` | `api` and authenticated API client name, or `producer` and authenticated producer name. Unavailable identity is `null`. |
| `gateway_config`, `gateway_node` | Logical APIServer identity for API calls; `null` for producer calls. A client name alone need not be globally unique. |
| `operation`, `user_id` | Fixed operation name and canonical decimal account ID, or `null` when parsing did not establish an ID. |
| `outcome`, `error` | `committed` with `null` error, or `rejected` with a fixed error code. |
| `config_revision` | Exact committed configuration revision as a decimal string; `null` for rejection. |
| `fields` | Public configuration leaf names selected by an edit, without values; creation/password operations use `account` and/or `credentials` markers. Same-value edits can still name their selected fields. |
| `identity_truncated` | Whether an actor/gateway label exceeded the bounded copied identity. Configured target/producer labels are validated when auditing is enabled. |

Both sources use public field spelling such as `enabled`, `notes`,
`limit.traffic.u`, `wireguard_allowed_ips` and `time.expire_at_ms`. No password,
derived credential, producer secret, token, request body or edited field value
is included. A successful event is queued at the actual revision commit, before
reply delivery. Losing a reply does not change that event into a rejection.
Producer `AddNewUser` retains its existing save-and-rollback behavior: a failed
save followed by rollback is rejected, not committed.

A fixed 256-record queue separates account operations from file output. Its short
mutex protects bounded metadata copies only; JSON rendering, disk I/O, rotation
and diagnostics run on one background writer. Queue-full or file failures never
roll back account changes or turn a committed acknowledgement into failure.
A full queue drops the new event and records degraded health. A file I/O failure
faults the writer for this instance: uncertain/partial bytes are never followed by
later records; queued and subsequent events are counted as dropped. Fix the
underlying issue and restart to resume file output. Normal shutdown drains
accepted records before freeing the writer; a previously faulted writer cannot
recover missing records.

`status.audit` is always present. It contains `enabled`, `healthy`,
`queued_records`, `written_records`, `dropped_records`, `write_failures` and
`last_error`. Counters are unsigned decimal strings and reset when this node is
created. `queued_records` excludes the record currently being written;
`written_records` counts successful append-and-flush operations. Independently
sampled counters describe current activity rather than a transactionally frozen
accounting equation. `healthy` stays false after a lost record or I/O failure.
`last_error` is `null` or a fixed code: `queue_full`, `sequence_exhausted`, `open`,
`write`, `flush`, `rotate`, `close`, or `invalid-file`. Status never exposes file
paths, native error text or record contents. Disabled logging reports healthy,
zero counters and a null error. The ordinary diagnostic logger also reports
startup/runtime audit errors.

Queued is not written, and flushed is not crash-durable. The audit file is not
atomically committed with the users database, has no per-record disk-sync
promise, no replay/recovery protocol and no tamper-evidence guarantee. Account
API success retains its existing in-memory meaning; audit events are operational
observations, not proof that a database save or client refresh completed.

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
A string-valued `password` or `pass` selects a standalone record; object-valued
entries named `password` or `pass` remain ordinary map entries. An existing
`password` field takes precedence over fallback `pass` during credential
validation, even if the selected field is malformed. A `users` wrapper takes
precedence over the other layouts. Import reserves at most 64 speculative records
above the existing count, then grows storage as entries validate. Failed append
restores existing records and indexes; allocated capacity may remain.
The saver always rewrites the database in the normalized `{"users": [...]}` form.

In this example, `password` is still the authentication lookup key. The `id` is a separate durable user identity: keep it
unique and stable for that user so Waterwall can do safe, fast lookups and carry local runtime state across user-table
refreshes.

### User JSON Structure

Before importing any layout, the file reader keeps the exact byte count and validates
the complete JSON document. Trailing non-whitespace bytes, concatenated documents,
raw or decoded NUL, invalid UTF-8 and duplicate decoded object keys reject the file.
Ordinary trailing JSON whitespace is allowed. An invalid primary follows the normal
backup-recovery path. These checks retain the existing cJSON nesting limit and do
not impose API-envelope byte or value-count limits on database files.

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
  it must contain exactly one CIDR, not a comma-separated list. Addresses require complete strict dotted-decimal IPv4
  or IPv6 syntax, including valid embedded IPv4 forms. Shorthand/octal/hex IPv4, oversized IPv6 groups and trailing
  garbage are rejected. Surrounding whitespace is trimmed; internal whitespace is invalid. Saved JSON normalizes the network address, so
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
  by `GetUsersPage`, and validated so configured ranges do not overlap between users.
- `id` is the durable logical user identity. Keep each non-zero id unique and stable for that logical user's lifetime;
  reusing an existing id for a different user can intentionally transfer client-side runtime state on the next
  `GetUsersPage` traversal.
- AuthenticationClient credentials are not stored in the user database. They live only in `settings.auth-clients`.
- The authoritative in-memory table tracks separate configuration and statistics revisions. These revisions are server
  metadata, not fields inside individual user objects.
- `AddNewUser` rejects duplicate usernames, duplicate durable user ids, duplicate password-derived lookup keys, and
  overlapping `wireguard-allowed-ips`, then saves the file immediately and bumps the configuration revision.
- `UpdateUser` selects an existing account by durable `id` and patches only explicitly supplied configuration leaves.
  It preserves usage, creation/first-use timestamps, credentials and live reservations. Each accepted nonempty patch
  advances the configuration revision once, including a same-value assignment, without an immediate file save.
- `PushUserStats` is the only remote usage-reporting operation. It accepts deduplicated traffic-byte deltas and advances
  the statistics revision when a new batch is accepted. Configuration-write and statistics-push permissions are separate.
- Startup loading validates lookup-table consistency. A corrupted primary file can be recovered from `db-path.backup`,
  but an invalid backup cannot be repaired automatically.
- Avoid editing both primary and backup files by hand while Waterwall is running. The periodic saver may overwrite
  manual edits with the current in-memory database state.

## Save Behavior

Under the server state write lock, saving stages the proposed database in the primary directory, stages the
previous committed primary as `db-path.backup`, publishes that backup, then atomically replaces `db-path`.
If opening the previous primary confirms that it is absent, saving publishes the
current valid in-memory table directly and leaves any existing recovery backup
untouched; no recovery backup is required. The next ordinary save resumes rotation.
An empty file or an open/read/close failure is not treated as absence.
Primary replacement is the commit point. Failure before it rejects `AddNewUser` and rolls its in-memory addition back;
the recovery backup never receives that rejected proposal. History/pruning or directory-sync failures after replacement
are logged and do not turn a committed addition into a rejected operation.

All primary, recovery, history and staging outputs are private before their first secret byte: exclusive `0600`
creation on POSIX and a protected Windows DACL granting the process user and SYSTEM access. Existing primary/recovery
permissions are restricted when loading; permission failure rejects startup. Writes, flush, file sync and close are
checked. Staging names are unique and are never startup recovery candidates. Cleanup removes only this operation's
staging files. Normal process shutdown saves a loaded database. Startup rollback
releases resources without a final save, preserving the primary and recovery bytes
when later construction fails. Weekly history slots use the local Monday-based
calendar, including weeks containing daylight-saving transitions or a year boundary.
This is not a guarantee of recovery from arbitrary filesystem or power-loss failures.

Clean periodic ticks skip serialization and staging only after one successful process-local primary checkpoint,
when no in-memory mutation is dirty, the primary opens as a nonempty regular file without following links, and no
history slot is due. The first periodic save, explicit forced saves, producer `AddNewUser` and normal final shutdown
still save. A successful producer creation saves the candidate and earlier dirty changes before its revision bump;
failure rolls it back while preserving earlier dirty state. Configuration/statistics commits mark dirty; exact usage
replay and session enrollment do not. A primary commit clears dirty even if optional history output fails; its history
slot remains due for retry. Missing-primary repair and backup protection remain unchanged.

Skipped ticks leave `.backup` and primary-save result/age telemetry unchanged. `database_dirty` and
`primary_checkpoint_valid` are process-local status facts. File open/type/empty/access/close failures are failures,
not successful skips. The health probe does not hash or validate externally edited JSON; editing a live database file
is not an account-update API. Saving remains synchronous under the state write lock, with the existing durability and
rollback rules.

For a damaged audit tail, stop every writer, preserve/quarantine the evidence privately, and deliberately repair or
select a valid audit file before restarting. For abandoned stage files, first stop all writers and remove only positively
identified stale private staging files. Never use broad wildcard deletion while a writer might be active. Stage files
contain plaintext credentials and are not startup recovery candidates.

The server securely wipes its owned producer secrets, decoded Authenticate fields and temporary password lookup copies
before release. Page rendering also clears its locally owned JSON/string copy before freeing it. APIServer and
the dispatcher separately clear their owned secret copies at final release. Configuration trees, parser-internal
partial trees, transferred transport/handler buffers and OS copies remain outside these guarantees; neither files
nor all process copies are erased.

## Startup Recovery

A valid primary is authoritative. If primary loading fails, the server validates `db-path.backup` and restores it
through the same private atomic writer. The backup remains available throughout and after restoration. Historical
snapshots are separate and are never automatic recovery candidates. If neither primary nor recovery backup is valid,
node creation fails. A pre-existing backup has no provenance metadata proving when its contents committed.

## Logic Explanation

The server owns one authoritative table and store-level `config_revision` / `stats_revision` counters, initially 1.
Configuration mutations bump the former; new usage batches and earliest first-use merges bump the latter. Independent point
reads share the state read lock. Authentication, saves and mutations hold its write lock. Whole-table/page reads share the read lock.

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
{"epoch":"<64 hexadecimal bytes>","sequence":1,"users":[{"id":42,"up":10,"down":0,"first-usage-at-ms":1792252800000}]}
```

`sequence` starts at 1 and advances without wrapping. Each batch has 1..4096 unique user IDs and both nonnegative
`up` and `down` deltas and a nonzero `first-usage-at-ms` per entry. Both deltas may be zero for metadata-only reports;
a valid next-sequence report is accepted even if its first-use minimum is unchanged. Integers are plain signed-64-bit-range
integer tokens or decimal strings through UINT64_MAX. Decimal/exponent number tokens are rejected by integer readers.
The root permits only `epoch`, `sequence` and `users`; each entry permits only `id`, `up`, `down` and `first-usage-at-ms`, all required.
Unknown or duplicate decoded keys reject the entire request, including nontraffic statistics, other timestamps and absolute
traffic totals. The complete byte span must be valid JSON/UTF-8 with no trailing data, raw/escaped NUL or more than eight
nested containers. These checks do not impose host-configuration file-size limits; authentication payload budgets apply.
The authenticated configured identity supplies the checkpoint key; payload fields cannot choose another identity.

Under one state write lock, the server validates epoch and sequence and hashes the exact payload bytes with SHA-256.
An exact replay of the last sequence/digest is acknowledged before current-account validation. Exactly the next
sequence validates every entry before any mutation, samples the accounting clock once, clamps each producer observation to that time, merges the smallest nonzero
first-use instant and applies saturating traffic, then
publishes its checkpoint. Older sequences, gaps, conflicting replay content, unknown IDs and duplicate IDs fail without
partial application. Only the current epoch's session may report. Checkpoint storage is constant per configured identity;
it contains no users-table snapshot or unbounded batch history.

The Ok ACK JSON contains `epoch`, `sequence`, a 64-character hexadecimal `digest`, and `needs-pull: true`.
The client validates all three batch identity fields, advances only the acknowledged subset's baseline, and pulls fresh
authoritative totals and first-use time. Pull installation preserves local post-snapshot traffic as `G + (A - B)`.
No full table is installed while a batch remains unresolved. Reconnect order is authenticate/resume, replay pending
batch, validate ACK, then pull. Blocked pull/push requests coalesce until this ordering permits them.
The client completes the required pull after authentication or each ACK before creating another usage batch. It then
gives a waiting push priority over ordinary periodic or explicit pulls; recurring pulls cannot starve usage reporting.

Epoch/checkpoint state is runtime-only. Accounting continuity across process crashes or restarts is not provided.
An unresolved batch whose continuity is lost stays identifiable and stops automatic synchronization for operator
reconciliation. With no uncertain batch, a client may enroll afresh and pull.

An ACK confirms acceptance in server memory, not a disk save. Periodic/final database saving retains its normal
semantics and does not save the producer checkpoint. A client restart can lose unreported usage; a server restart can
lose acknowledged usage since its last successful save and loses its retry checkpoints. Shutdown does not guarantee
final usage delivery. There is no accounting crash recovery or remote usage-reset operation.

Traffic-serving nodes use AuthenticationClient handles and copy-out APIs; they never receive borrowed user pointers.
Credential eligibility checks enabled state, expiry and cumulative traffic. Live connection/IP admission remains local
to one client runtime; saved gauge values do not reserve or exhaust live capacity. The protocol has no encryption of
its own. It carries producer credentials and full user records, including user credentials. Untrusted remote links
require authenticated encryption with server identity verification. A supported composition is
`AuthenticationClient -> TlsClient -> TcpConnector` with `TlsClient` settings `{"sni":"auth.example.com","verify":true}`,
paired with `TcpListener -> TlsServer -> AuthenticationServer` using the server certificate and key. The loopback
examples describe local deployment. A response MAC alone would not protect confidentiality.

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

The entire envelope is validated before any request executes, including a maximum of 64 frames. Frame 65 rejects
all siblings without applying earlier mutations. A malformed envelope closes the borrowed logical connection;
verbose mode provides bounded diagnostics without unconditional per-frame warnings.

After the four-byte length and 64-byte token arrive, a currently valid token permits the ordinary message limit.
Without one, frame payload is limited to 16 KiB, excluding the outer 68 bytes; an oversized declaration closes
immediately without waiting for its body. Tokens are revalidated at dispatch. Large messages whose token was replaced
or expired close without executing; small stale-token requests retain correlated `authentication-required` replies.
The session at envelope entry governs all siblings: a successful Authenticate does not authorize sibling requests.

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
- `9`: `GetUsersPage` (`GetAllUsers` C alias)
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
also require `allow-user-pull`; user create/update modules require `allow-user-write`; `PushUserStats` requires
`allow-stats-push`. Neither write permission implies the other. Opcode `8` is unsupported and receives the ordinary
`unknown-request-type` error.

### Authenticate Module

Request data is `{"name":"edge-1","secret":"long-random-secret"}` for fresh enrollment, or the same object
with `"epoch":"<64 hexadecimal bytes>"` for resumption. The outer token is zero. Success returns type `4` and
128 bytes: token then epoch, 64 hexadecimal bytes each. Later requests carry the token in their envelope.
Authenticate data is at most 16,375 bytes, with strict quiet JSON parsing, depth two and eight lexical values.
Only nonempty string `name`/`secret` and optional valid `epoch` are accepted; duplicate/unknown keys, trailing bytes,
invalid encoding and decoded NUL are refused. After a failed Authenticate, admission closes before handing off its
correlated response. Pause/Resume can finish that queued response; further input closes the line.
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

All password and digest lookup modules admit the complete compact JSON size before copying the matched user's strings.
The JSON must fit the 16 MiB response payload limit minus its 9-byte frame header. A record one byte over that limit
returns `response-too-large`; it is never truncated. Invalid stored string encoding returns `user-json-serialize-failed`.
The collection remains locked through the bounded copy so a concurrent removal cannot invalidate the selected account.

The `AddNewUser` module expects request data containing a JSON object for one user, using the AuthenticationServer user
format described above. The submitted user must contain a non-zero unique `id`/`user-id`.

The module validates the complete payload before constructing credentials: UTF-8 must
be valid, object keys must be unique after decoding, raw/decoded NUL is forbidden,
and only JSON whitespace may follow the object. Malformed input leaves users,
configuration revisions and database files unchanged. Valid Unicode password bytes
and the `password`/`pass` aliases retain their normal meaning. It then checks that
the user can be created and that the new user's id, name, and password hashes do not
conflict with existing users. If validation passes, the user
is added to the in-memory database and the users file is saved immediately through the private atomic commit sequence.
If that immediate save fails, the module attempts to roll back the in-memory add and returns a save error.

On success it returns response type `0` and response data equal to `user-added`.

If validation or saving fails, it returns an error response frame with the same correlation ID. If the file save fails
after the in-memory add succeeds, the module attempts to remove that user from memory and returns
`database-save-failed`.

`storage-unavailable` reports rejected user storage/index capacity or failure to initialize the native locks for a
copied user. Heap exhaustion terminates the process instead of producing an error response.

### UpdateUser Module

`UpdateUser` takes a configuration patch with a required nonzero exact unsigned 64-bit `id`. For example:

```json
{"id":42,"name":"Alice"}
```

If an administrator read 100 bytes and a batch added 10 more, this name edit leaves 110 bytes intact. No password or
full exported user is submitted. Omitted fields, including siblings inside nested objects, retain their stored values:

```json
{"id":42,"limit":{"traffic":{"total":1073741824}},"time":{"expire-after-first-usage-ms":86400000}}
```

This changes only total traffic quota and the expiry duration; upload/download quotas, other limits, absolute expiry,
creation/first-use time and all counters stay intact.

| Editable leaf | Type |
| --- | --- |
| `name`, `email`, `notes`, `wireguard-allowed-ips` | String; empty string clears it under existing index/CIDR rules |
| `gid` | Exact unsigned 64-bit integer |
| `enabled` | JSON boolean |
| `record-stat-interval-ms` | Exact nonnegative integer through INT_MAX; no reporting scheduler is introduced |
| `limit.traffic.up`, `.down`, `.total` | Exact unsigned 64-bit integers |
| `limit.bandwidth.up`, `.down` | Exact unsigned 64-bit integers |
| `limit.ips`, `.devices`, `.connections-in`, `.connections-out` | Exact unsigned 64-bit integers |
| `time.expire-at-ms`, `.expire-after-first-usage-ms` | Exact unsigned 64-bit integers |

Dotted paths mean nested objects. Zero clears the corresponding limit/expiry. Integer tokens through INT64_MAX and
decimal strings through UINT64_MAX are supported; negatives, fractions, decimal/exponent tokens and overflow reject.
At least one editable leaf is required. Null, empty supplied containers, unknown/case-variant/alias keys, duplicate
decoded keys, malformed UTF-8, raw/escaped NUL, excessive nesting and trailing non-whitespace data reject the whole
patch. `stats`, passwords/hashes/credentials, alternate IDs, runtime/client-view fields, creation time and first-use time
are forbidden, including their top-level aliases. A valid field alongside a forbidden one does not apply.

Name and Allowed-IP indexes are prepared before commit. Unknown ID, duplicate name, invalid/overlapping CIDR and
expected capacity refusal change no account fields, logical indexes, revisions or accounting checkpoint. Successful
patches return type `0`, `user-updated`, and increment only `config_revision` exactly once under server write
serialization. They edit memory without immediately saving it. Independent patches preserve one another's omitted
fields; for the same field, the latest accepted value wins. No expected-revision precondition is required.

### Statistics Ownership

Account traffic counters and traffic limits use charged quota bytes. AuthenticationClient applies its configured
`traffic-multiplier` to new measured bytes before reporting; AuthenticationServer never applies another multiplier.
Other producers and database imports must also supply charged usage. At the default multiplier of `1`, charged and
measured bytes are equal. Aggregates from different rates cannot be converted back to actual network traffic; speed
and other nontraffic statistics keep their own units.

| Value | Owner and current rule |
| --- | --- |
| Cumulative charged upload/download bytes | Server aggregate; remote changes use accepted deduplicated batches. Config patches preserve it. |
| First-use timestamp | Earliest nonzero accounting observation from authorized producers, clamped to accounting receipt time. Config patches preserve it. |
| Creation timestamp | Creation/import metadata, preserved by ordinary edits. |
| Limits, enabled flag, expiry policy | Account configuration changed through explicit patch leaves. |
| Active outbound connections and IP reservations | Local runtime admission state, retained/released locally; no global count is supplied. |
| Stored/imported IP, device, connection and speed statistics | No reliable live global occupancy view and no admission source. This protocol adds no reporting of these gauges. |

Future connection telemetry needs producer scope, sample order and expiry: a later snapshot replaces an earlier one,
so repeated samples must not be added like traffic. Speed needs a measurement window/time and freshness; stale/missing
samples are not measured zero and compatible producer windows are required before aggregation. Distinct-IP telemetry
needs an identity set, observation window and cross-producer deduplication; adding client counts cannot produce a
global distinct count. Device reporting needs defined device identity and collection. Reset requires a separate policy
for delayed usage and distributed cutoffs; no reset operation is provided here.

### GetUsersPage Module

Request `9` (`GetUsersPage`, also named `GetAllUsers` in the C interface) returns one bounded credential-bearing page.
There is no whole-table fallback. Every request needs the current producer token, `allow-user-pull`, and its exact
acknowledged accounting checkpoint. Sequence and digest are zero at enrollment:

```json
{"epoch":"<64 hex characters>","sequence":"0","digest":"0000000000000000000000000000000000000000000000000000000000000000"}
```

A continuation adds `"cursor":"<64 lowercase hex characters>"` and `"total":"130"`. The cursor encodes the 16-byte
server instance ID, 64-bit configuration revision and 64-bit next collection position, in that order. It is a stateless
position hint and grants no permission. The request is at most 1024 bytes, uses strict quiet JSON with depth two and
16 values, rejects unknown/duplicate fields, and uses canonical unsigned decimal strings for sequence and total.

Each response has type `3` and this schema (all unsigned 64-bit metadata are decimal strings):

```json
{
  "instance":"<32 lowercase hex characters>",
  "epoch":"<64 hex characters>",
  "sequence":"0",
  "digest":"<64 hex characters>",
  "config-revision":"1",
  "stats-revision":"1",
  "server-time-ms":"1767225600000",
  "accounting-time-ms":"1767225600000",
  "total":"0",
  "position":"0",
  "count":"0",
  "cursor":"<64 lowercase hex characters>",
  "complete":true,
  "validated":false,
  "users":[]
}
```

The `users` array contains exactly `count` complete user records, including credentials. Ordinary pages target 256 KiB
of complete encoded response and at most 128 users. A first record larger than that target occupies a page by itself,
up to the existing 16 MiB hard response framing limit after all metadata/frame overhead. `user-too-large` rejects a
record that cannot fit; fields are never truncated. Size admission precedes copying arbitrary-length row strings, and
only bounded page state is retained. No frozen full-table snapshot is kept on the server.

A last data page has `complete:true`, `validated:false` and a terminal cursor. The client must then send that cursor,
the same total/checkpoint and `"validate":true`. The server returns a small `complete:true,validated:true` response,
with `position == total`, `count:"0"` and an empty `users` array. An empty table has one empty complete data page and
uses the same final validation. Validation acknowledges no usage.

Any configuration edit, including a same-value edit, invalidates continuation/final validation with `stale_cursor`.
Wrong totals or positions return `invalid_cursor`; epoch/sequence/digest contradictions return
`accounting-continuity-lost`. Traffic/first-use changes from other producers do not invalidate configuration cursors.
Each page samples statistics and clocks separately, so the installed statistics revision is a conservative first-page
revision, not an atomic whole-table statistics snapshot. Per-page request deadlines allow a progressing traversal to
outlast the former single-response deadline. The client serves its old cache until final validation and atomic install.

The server executes page reads under the envelope's existing shared state lock (exclusive for a mixed mutation
envelope), releases it before transport callbacks, and never recursively acquires it in the handler. The 64-frame cap,
entry-session authorization, token revalidation and bounded response queue remain in force.

`server-time-ms` and positive `accounting-time-ms` are response-only values. Absolute dates use the wall sample; the
accounting clock advances from its construction wall/monotonic anchor without rebasing on later wall corrections.
The client preserves each page's clock pair and receipt time when installing that page's users.

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

- The current authenticated outer message payload limit is 16 MiB; unauthenticated payload is limited to 16 KiB.
- The current request data limit is 16 MiB.
- The current response payload limit is 16 MiB.
- Queued and active responses share 1024 entries, 16 MiB plus the 20-byte envelope in logical storage, and 32 MiB
  allocation charge. Refusal closes only that line and releases all retained storage.
- Responses drain in FIFO order through at most 16 KiB stream chunks, preserving chain padding and nested callback
  order. Pause gates endpoint output; active backing allocations remain charged until release.
- Temporary construction retains at most one bounded response frame, one growing message (each at most 16 MiB plus
  envelope), one bounded serialized JSON text (16 MiB plus five spare printer bytes), and one output chunk. Allocation
  replacement may briefly overlap old/new storage. Message construction grows capacity geometrically within the cap. JSON trees, account tables, pools and transport queues are separate;
  this budget is not a total-RSS bound.
- Complete request messages drain before checking incomplete-input limits; combined messages are not oversized frames.
  Incomplete input with a validated token stays below 16 MiB plus the 68-byte envelope, with at most 1024 fragments and
  32 MiB allocation charge after compaction. Unvalidated input retains at most 16 KiB plus 68 bytes, 64 fragments and
  the greater of 128 KiB or one pool best-fit allocation for that maximum envelope. Nested delivery and older unread
  bytes share their applicable allowance; a valid predecessor never authorizes an oversized unvalidated successor.
  Ordinary nested input retains the existing one-maximum-message plus 2 MiB ceiling. Empty deliveries are recycled.
  One extracted request and a compaction destination are bounded parsing scratch; the current synchronous delivery is
  outside the retained bound.
- Synchronization is paged: ordinary pages target 256 KiB/128 users and one exceptional record may use the hard
  response limit. The client defaults to 100,000 users and 256 MiB encoded user-record bytes per complete traversal;
  active/baseline/staged tables, indexes, parsing and runtime queues consume additional RAM. Account count is not a
  fixed users-per-16-MiB estimate.

- This node does not require left padding and does not prepend in-place.
- This node is not a packet tunnel and does not use packet-line semantics.

## Management API

The server explicitly registers read-only `status`, `get-user` and `list-users`,
and writable `update-user`, `create-user` and `change-user-password`, for
[APIServer](APIServer.mdx). Each operation takes an `application/json` body and
returns UTF-8 JSON. Configure an independent operator token and exact permissions
on the gateway, for example:

```json
{"config":"central","node":"auth-db","operations":["status","get-user","list-users"]}
```

A `status` permission grants no account-read permission. `get-user` and
`list-users` apply to all accounts on the selected server; cursors carry no
permission. Every continuation must authenticate and pass the gateway allowlist.
Read operations do not authenticate traffic users, change accounts, synchronize
clients or trigger a database save. `update-user` conditionally edits configuration
in memory; `create-user` creates a fresh account with a caller-supplied ID and
password; `change-user-password` conditionally replaces an existing account's
credentials while preserving its identity and accounting. Each write has its own explicit permission. They expose no passwords, hashes, UUID
credentials, WireGuard keys, producer secrets or session tokens.

All bodies are strict JSON objects: unknown/duplicate keys, malformed UTF-8, decoded
NUL, trailing input and incorrect types are rejected. Read bodies are limited to
4096 bytes, depth two and 16 lexical values; mutation bodies use the separate bounds
below. All numeric result leaves, including
IDs, revisions, counts, limits, bytes and times, are canonical unsigned decimal
**strings**; `enabled` remains a boolean. Account IDs in requests must also be
canonical decimal strings, from `"1"` through `"18446744073709551615"`, with no
sign or leading zero. This preserves IDs above JavaScript's exact integer range.

Every successful read includes one top-level `edit_token`, sampled with its
configuration revision. It is an opaque 48-character lowercase hexadecimal value
binding the server instance to that revision, and is an optimistic edit
precondition rather than an authentication credential. A list page has one token
for the page. The existing 64-character pagination cursor remains separate.

### `status`

The body is exactly `{}`. A successful body has this shape:

```json
{
  "database_loaded": true,
  "user_count": "1200",
  "configured_producer_count": "4",
  "session_record_count": "5",
  "config_revision": "84",
  "edit_token": "000102030405060708090a0b0c0d0e0f0000000000000054",
  "stats_revision": "1902",
  "primary_save": {
    "last_result": "success",
    "last_attempt_age_ms": "3200",
    "last_success_age_ms": "3200"
  },
  "audit": {
    "enabled": false,
    "healthy": true,
    "queued_records": "0",
    "written_records": "0",
    "dropped_records": "0",
    "write_failures": "0",
    "last_error": null
  }
}
```

`session_record_count` counts retained authentication sessions, not live control
connections, traffic connections, online users or devices. Save history is
process-local: `last_result` is `not_attempted`, `success` or `failure`. Before the
first runtime save both ages are `null`; loading/recovery does not count as an
attempt. Ages use monotonic elapsed milliseconds at the primary-save outcome.
A later failure preserves the previous successful-save time. Primary replacement
is the existing commit boundary; optional history-backup failures and subsequent
directory-sync warnings do not turn it into a failed save or strengthen its
power-loss guarantee.

### `get-user`

Request `{"id":"42"}`. The result contains `config_revision`, `stats_revision`,
`accounting_time_ms`, `edit_token` and `user`. The `user` field contains exactly:

| Fields | Meaning |
| --- | --- |
| `id`, `gid`, `enabled` | Stored durable identity, group and enabled setting. |
| `name`, `email`, `notes`, `wireguard_allowed_ips` | Complete permitted strings; absent values are empty strings. No keys or credentials are included. |
| `record_stat_interval_ms` | Configured statistics interval. |
| `limit.traffic.u`, `.d`, `.total` | Stored upload, download and combined limits in charged quota bytes. |
| `limit.bandwidth.u`, `.d` | Actual logical bytes per second, upload/download independently; zero is unlimited. UserController shares each user's local allowance across lines and workers of one AuthenticationClient. |
| `limit.ips`, `.devices`, `.cons_in`, `.cons_out` | Stored limits; presence does not assert enforcement by every traffic node. |
| `time.created_at_ms`, `.expire_at_ms` | Existing wall-clock creation and absolute-expiry values. |
| `time.expire_after_first_usage_ms` | Relative-expiry duration. |
| `time.first_usage_at_ms` | Server accounting-clock first-use observation. |
| `usage.u`, `.d` | Cumulative charged usage accepted by this server. |

Zero/default values are explicit and retain their existing sentinel semantics.
`accounting_time_ms` is the current server accounting-clock reference, sampled
with the revisions and account. The view computes no derived expiry/admission
decision. Disconnected clients may retain unreported usage debt. Stored speed,
connection, IP and device gauges are not live synchronized statistics and are
excluded along with client-local accounting and runtime enforcement state.

A missing valid ID returns `not_found`. Complete details are never truncated:
a permitted record that exceeds the bounded operation returns `record_too_large`;
malformed stored UTF-8 returns `invalid_record_encoding`.

### `list-users`

`{}` starts a traversal with a default limit of 50. `{"limit":1}` selects an
integer limit from 1 through 100; continue with
`{"limit":50,"cursor":"<returned opaque cursor>"}`. The limit may change between
pages. Empty/null/malformed supplied cursors are errors.

```json
{
  "config_revision":"84",
  "edit_token":"000102030405060708090a0b0c0d0e0f0000000000000054",
  "stats_revision":"1902",
  "accounting_time_ms":"1800000000000",
  "total_users":"1200",
  "users":[{
    "id":"42","gid":"7","enabled":true,
    "name_preview":"Alice","name_preview_state":"complete",
    "traffic_limit":{"u":"0","d":"0","total":"1000000000"},
    "usage":{"u":"2500","d":"8000"},
    "time":{"expire_at_ms":"0","expire_after_first_usage_ms":"86400000","first_usage_at_ms":"1800000000000"}
  }],
  "next_cursor":"<returned opaque cursor>"
}
```

Summary fields are exactly those shown; use `get-user` for other permitted
configuration. `name_preview` ends at a complete UTF-8 codepoint within 256 bytes.
Its state is `complete`, `truncated`, or `invalid_encoding`; an invalid inspected
prefix produces a null preview and does not prevent traversal. The uninspected
tail of a large name is not validated, and listing does not scan email or notes.

Order follows the current collection, with no ID/name sort guarantee. Treat the
64-character cursor as opaque and process-local. Configuration revision changes,
including an accepted same-value edit or addition, make earlier cursors
`stale_cursor`; restart without a cursor. Restarting/recreating a server also
invalidates its cursors. Statistics-only changes and first-use observations do
not invalidate them; each page may report newer usage. Pages are not a frozen
traffic snapshot. With unchanged configuration, traversal visits each account
once. `next_cursor: null` marks the end.

The limit is an upper bound: response/memory limits can yield a smaller nonempty
page. No successful page skips unreturned records. If one summary cannot fit,
return `response_too_large`. Timeout/contention discards partial work rather than
returning a partial-success cursor.

### `update-user`

An editor needs explicit `get-user` and `update-user` permissions. Monitoring
permissions stay read-only; producer credentials and `allow-user-write` do not
grant access through APIServer. Read the account first and put its `edit_token`
in `if_match`:

```json
{
  "id":"42",
  "if_match":"000102030405060708090a0b0c0d0e0f0000000000000054",
  "patch":{
    "enabled":false,
    "limit":{"traffic":{"total":"1000000000"}},
    "time":{"expire_at_ms":"0"}
  }
}
```

Exactly `id`, `if_match` and a nonempty `patch` are required. Use snake_case and
`u`/`d` in this API; the existing producer protocol keeps its separate spellings.
A patch contains only the intended changed leaves. Omitted fields and siblings
remain unchanged. These leaves are editable:

| Patch leaves | Accepted values |
| --- | --- |
| `name`, `email`, `notes`, `wireguard_allowed_ips` | UTF-8 strings; empty string clears the field. Name uniqueness and Allowed-IP validation/overlap rules still apply. |
| `gid` | Canonical unsigned decimal string, including `"0"`. |
| `enabled` | JSON boolean. |
| `record_stat_interval_ms` | Canonical decimal string from `"0"` through INT_MAX. |
| `limit.traffic.u`, `.d`, `.total`; `limit.bandwidth.u`, `.d` | Canonical unsigned decimal strings; traffic is charged quota bytes, bandwidth is actual logical bytes per second. |
| `limit.ips`, `.devices`, `.cons_in`, `.cons_out` | Canonical unsigned decimal strings. |
| `time.expire_at_ms`, `.expire_after_first_usage_ms` | Canonical unsigned decimal strings, preserving zero sentinels and clock/duration semantics. |

Unsigned values allow zero and extend through UINT64_MAX unless the interval
range above is narrower. Signs, whitespace, leading zeros, fractions and overflow
are invalid. Account IDs remain nonzero. Empty nested objects, null, unknown or
duplicate keys, incorrect types and protected fields reject the whole request.
ID changes, passwords/derived keys, creation/first-use times, usage, statistics,
runtime reservations and accounting checkpoints cannot be patched. Do not send a
whole `get-user` result as a patch. Disabled and expired accounts remain editable.
Configuring a limit does not add enforcement support to other nodes.

Successful acknowledgement:

```json
{
  "id":"42",
  "config_revision":"85",
  "edit_token":"000102030405060708090a0b0c0d0e0f0000000000000055"
}
```

The supplied token must match both this server instance and its current
server-wide configuration revision. An unrelated account edit can cause
`conflict`; a token from an earlier server instance also conflicts. Every accepted
nonempty patch, including a same-value patch, increments the revision once and
returns that transaction's token. Statistics pushes and exact replay leave edit
tokens valid. Reusing an old token after success cannot apply the edit twice.

The response confirms an **in-memory commit**. It does not acknowledge a disk
save, client refresh or immediate disconnection of existing traffic. API edits
do not initiate saves or change primary-save history. Existing periodic/final
saving continues, and a crash can lose unsaved changes. Connected clients receive
policy through ordinary synchronization; disconnected clients retain cached
policy until refresh. Usage, first-use evidence, credentials, runtime state,
accounting checkpoints and `stats_revision` are preserved. The authorized producer
protocol continues sharing the same configuration revision; its preceding edits
can make tokens stale, and its later edits remain later writes.

Update bodies are limited to 32 KiB, four object levels and 64 lexical values.
Preparation, index work, deadlines and allocator charge are bounded before commit.
Renaming a record whose existing name exceeds the 32 KiB inspection allowance
returns `resource_limit`; other edits do not inspect that name. New Allowed-IP
index growth is capped at 1 MiB and the remaining working allowance. These are
operation bounds, not new database import limits. Expected refusals leave account
values, index membership and revisions unchanged; private reserved capacity may
remain. The compact acknowledgement is prepared before mutation, is bounded to
256 body bytes, and fits the gateway's minimum 1024-byte envelope even with a
maximally escaped request ID.

Node-result failure codes are `invalid_request`, `conflict`, `busy`, `not_found`,
`invalid_allowed_ips`, `name_exists`, `allowed_ips_overlap`, `resource_limit`,
`response_too_large`, `timeout` and `revision_exhausted`. A returned operation-level
failure means this edit did not commit. `conflict` does not include a fresh token:
reread and reconsider the intended changes. Configuration revision UINT64_MAX
refuses further API and producer configuration mutations before changing accounts.

A lost response, disconnect, late gateway timeout or other post-dispatch delivery
failure means **outcome unknown**: the edit may already have committed. Reread
first, compare the intended values using their normal semantics, including
normalized Allowed-IP strings, then decide whether another patch is appropriate.
Never automatically fetch a fresh token and replay the old patch. Request IDs
provide correlation, not deduplication, and there is no persistent idempotency or
recovery record. The example client performs no automatic write retries.

### `create-user`

Creation requires its own exact `create-user` gateway permission. An editor's
`update-user` permission, producer credentials and protocol `allow-user-write`
do not grant it. A creator normally also needs `get-user` to inspect uncertain
outcomes. The caller supplies both a unique permanent account ID and the initial
password; no edit token is required:

```json
{
  "id":"43",
  "password":"example-only-secret",
  "config":{
    "name":"alice",
    "enabled":false,
    "limit":{"traffic":{"total":"100000000000"}},
    "time":{"expire_after_first_usage_ms":"2592000000"}
  }
}
```

**Omitting `config`, or supplying `{}`, creates an enabled account with unlimited
or unset zero policy limits and expiry.** Explicitly send `"enabled":false` for
staged provisioning. Defaults preserve ordinary fresh-account construction:

| Configuration leaves | Default |
| --- | --- |
| `name`, `email`, `notes`, `wireguard_allowed_ips` | Empty string. |
| `gid` | `"0"`. |
| `enabled` | `true`. |
| `record_stat_interval_ms` | `"120000"`. |
| `limit.traffic.u`, `.d`, `.total`; `limit.bandwidth.u`, `.d` | `"0"`. |
| `limit.ips`, `.devices`, `.cons_in`, `.cons_out` | `"0"`. |
| `time.expire_at_ms`, `.expire_after_first_usage_ms` | `"0"`. |

These are exactly the 18 public configuration leaves accepted by `update-user`,
with the same types, canonical integer ranges, zero meanings, name uniqueness
and Allowed-IP normalization/overlap checks. An empty top-level `config` is
allowed; supplied nested `limit`, `traffic`, `bandwidth` and `time` objects must
be nonempty. Configuration cannot supply identity, password, derived keys,
creation/first-use timestamps, usage, statistics, runtime state or checkpoints.
Configuring a limit adds no enforcement capability to other nodes.

The only root keys are required `id`, required `password` and optional `config`.
ID is a canonical nonzero unsigned decimal string through UINT64_MAX, preserving
values above JavaScript's exact integer range. Password is a nonempty UTF-8
string, preserved byte-for-byte without trimming, normalization or an additional
strength policy. Decoded NUL, malformed UTF-8, JSON numbers for integers, signs,
leading zeros, null, unknown/duplicate keys, protocol aliases and trailing input
are rejected. Root `if_match`, `edit_token` and `request_id` are invalid. The
complete node body is capped at 32 KiB, lexical depth four and 64 lexical values
including keys, checked before JSON-tree construction.

Credentials are derived using the ordinary SHA-224, SHA-256 and WireGuard helpers;
UUID identity exists only for a UUID-form password. Creation time is generated
by the server's wall-clock constructor. Usage, first-use timestamp, runtime
counters/reservations and client-local timing start empty or zero. Creation,
readback and synchronization do not count as first traffic. Public responses,
including reads, never expose the password or derived identities.

Success returns exactly the ID and the revision/token of this transaction:

```json
{
  "id":"43",
  "config_revision":"86",
  "edit_token":"000102030405060708090a0b0c0d0e0f0000000000000056"
}
```

Creation increments configuration revision once, invalidating older edit tokens
and pagination cursors; statistics revision, all existing accounts and producer
checkpoints remain unchanged. Independent valid creations can both succeed,
and an unrelated edit does not itself invalidate a creation request. The token
returned by creation can be used for a subsequent conditional edit while current.

Creation is create-only. Existing ID yields `id_exists`, even for an identical
request; it never replaces an account or acknowledges a duplicate as replay.
With the collection locked, ID is checked before other duplicate classes.
Conflicting nonempty name yields `name_exists`; any duplicate SHA-224, SHA-256,
UUID or WireGuard identity yields `credentials_exist`, without identifying the
conflicting account. Different password text can share a derived identity.
Concurrent same-ID requests can return one success and `busy` or `id_exists`;
a later attempt with that ID returns `id_exists`.

Node failures are `invalid_request`, `id_exists`, `name_exists`,
`credentials_exist`, `invalid_allowed_ips`, `allowed_ips_overlap`, `busy`,
`resource_limit`, `creation_failed`, `response_too_large`, `timeout` and
`revision_exhausted`, in the usual fixed `{"error":{"code":"id_exists"}}`
shape. Backend/crypto or native-lock initialization refusal is `creation_failed`.
Earlier malformed-input, budget, backend or contention failures can precede
duplicate checking. A returned node-operation failure publishes no account.

Preparation, aggregate new storage/index allocation, scratch, temporary overlaps
and the actual result-pool allocation must fit the remaining handler working
allowance. `resource_limit` can require a larger existing APIServer
`handler_working_memory` setting; creation has no separate 1 MiB total-growth
limit. A name-map rehash additionally inspects stored names within a cumulative
byte-work budget equal to the supplied working allowance. Oversized legacy names
can therefore refuse growth; spare name-map capacity avoids this full scan.
Checks occur between bounded reserve stages; native rehash/crypto calls are
finite synchronous work, without a strict wall-clock latency guarantee. Capacity
reserved before a later refusal may remain private, while account membership,
counts, stable pointers and revisions remain unchanged. The 256-byte ACK and its
actual pool charge are reserved and rendered before publication; it fits the
minimum 1024-byte gateway envelope, including a maximally escaped correlation ID.

Success acknowledges an **in-memory commit**. The API initiates no save and
changes no primary-save telemetry. Ordinary periodic/final saving persists it
later; a crash can lose an unsaved account. Producer `AddNewUser` keeps its
existing synchronous save-and-rollback behavior. Connected AuthenticationClients
obtain the account and credentials through normal synchronization; an offline
client cannot admit this previously unknown account until refresh. Existing
pending usage remains intact. Success does not prove every client has refreshed.

A lost reply, disconnect, abandoned completion or post-dispatch gateway timeout
means **outcome unknown**. Retain the original ID and intended inputs, then read
`get-user` for that ID. If present, inspect the permitted configuration: existence
does not prove your request created it, and redacted reads cannot prove its
password after a competing creation. If absent, explicitly decide whether to
retry the same ID and original inputs; the first request may still be running.
Never automatically select another ID, replace an existing account, reset its
credentials or interpret `id_exists` as proof of earlier success. Outer request
IDs provide correlation, not idempotency. The caller allocates IDs and should not
reassign an ID to another person/account; uniqueness covers the current
collection, without a persistent history of all previously used IDs or a
cross-crash exactly-once guarantee. The example client never retries writes.

### `change-user-password`

This administrator operation needs its own exact APIServer permission. A password
administrator normally receives only `get-user` and `change-user-password` for
this server. Monitoring, editor, creator and producer credentials gain no
password-change access. Read the account first, then submit exactly:

```json
{
  "id":"42",
  "if_match":"000102030405060708090a0b0c0d0e0f0000000000000056",
  "password":"example-only-new-secret"
}
```

`id` is a canonical nonzero unsigned decimal string through UINT64_MAX.
`if_match` is the current 48-character lowercase hexadecimal edit token. The
caller chooses a nonempty UTF-8 `password`; decoded bytes are preserved without
trimming, case folding or Unicode normalization. There is no old-password
challenge, generation, strength/history policy or alternate `new_password`
spelling. Reject missing/extra/duplicate keys, incorrect types, nested objects,
null, BOM, malformed UTF-8/Unicode escapes, decoded NUL and trailing input.
The body is limited to 32 KiB, depth one and 16 lexical values including keys,
checked before JSON-tree allocation. Other operation/import limits are unchanged.

Both instance and server-wide configuration revision must match before the ID
is resolved. An unrelated edit or creation can produce `conflict`; statistics,
first-use observations and exact usage replay leave the token valid. A current
same-password assignment is accepted and advances configuration revision once.
It is not replay success; reuse of the previous token conflicts. Disabled,
expired and traffic-exhausted accounts remain administratively editable.

Success uses the existing compact mutation schema:

```json
{
  "id":"42",
  "config_revision":"87",
  "edit_token":"000102030405060708090a0b0c0d0e0f0000000000000057"
}
```

The result names this transaction's in-memory commit, without exposing plaintext
or derived values. It invalidates previous edit tokens and pagination cursors.
Configuration revision UINT64_MAX refuses before mutation; the preceding final
representable transition remains valid. The existing 256-byte acknowledgement
and maximum-envelope proof also apply here.

The server derives the same plaintext hash, SHA-224, SHA-256, UUID validity and
WireGuard public-key values as ordinary user construction. It changes only
credentials and their four index memberships. The account's address, ID, count,
order, name/group/enabled/contact metadata, policy, Allowed-IP configuration,
creation/first-use times, statistics, traffic and reservations remain intact.
`stats_revision` and producer epochs/sequences/digests do not change.

Credential uniqueness covers every valid derived identity belonging to other
accounts; `credentials_exist` reveals no conflicting account or key. A matching
identity already owned by the target is allowed. UUID semantics follow password
parsing: plain-to-UUID adds the UUID identity, UUID-to-plain removes it, and
UUID-to-another-UUID replaces it. Different case spellings of the same UUID keep
that UUID identity: they conflict across accounts but are allowed for the same
account. The new exact plaintext matches and a different previous plaintext no
longer matches. Derived identities whose bytes changed stop resolving; an
unchanged UUID identity can remain usable after a textual case change. This is
not a blanket promise that every textual password change revokes every protocol
identity. It adds no WireGuard integration.

Preparation and credential derivation happen once before shared locking. The
transaction tries state, collection and target configuration write locks, without
waiting or taking the statistics lock. It uses reserved credential-index capacity
rather than growing/rehashing maps or scanning users. The existing password must
terminate within 32 KiB plus one terminator byte; a larger imported value returns
`resource_limit` without change. This is an operation bound, not a database import
restriction. The prepared/decoded secret copies and replaced object-layer plaintext are securely wiped on their
owned cleanup paths. Raw transport and configuration buffers are not comprehensively wiped.

Expected node errors are `invalid_request`, `conflict`, `not_found`,
`credentials_exist`, `busy`, `resource_limit`, `password_change_failed`,
`response_too_large`, `timeout` and `revision_exhausted`. They use the fixed error
body, and a returned node-operation failure guarantees this invocation did not
commit. Budget, parsing, crypto and contention refusals can precede duplicate
checking. The reserved ACK is rendered before commit; subsequent reply loss
cannot roll the credentials back.

Connected AuthenticationClients obtain the new table through ordinary refresh.
Offline clients continue accepting the old credentials under cached policy until
a valid refresh, and new credentials become available there only afterward.
Refresh migrates pending traffic, exact batch retry bytes, first-use evidence/age,
ACK state, expiry projections and reservations by durable ID. Existing admitted
connections continue accounting and policy enforcement; a password change does
not force their termination. Their original handles can still release migrated
reservations. Success does not prove immediate global revocation or that every
client refreshed.

No immediate save occurs and primary-save history stays unchanged. Existing
periodic/final saving later persists the change; a crash can lose unsaved work.
There is no journal, durable request record or crash-recovery protocol.

A lost/invalid reply, disconnect or post-dispatch gateway timeout leaves the
outcome unknown. Keep the intended ID/password securely and reread the account
for current public values and an edit token. **Redacted reads cannot prove which
password is stored**; an advanced revision can also come from another edit.
Explicitly decide whether to submit the same desired password with the new token.
A successful resubmission establishes it at that transaction's commit point,
without proving the earlier outcome or preventing later authorized changes.
On conflict, reread and reconsider again. Never automatically fetch a token,
replay a write or generate a different recovery password. Request IDs remain
correlation only, with no retry-result cache or replay shortcut.

### Bounded snapshots and errors

Reads run on the calling event worker, acquiring the server, collection, user
configuration and statistics read locks without waiting. Contention returns
`busy`, including while an existing save holds the state write lock. A busy
query does not indicate database failure. Values are copied coherently under the
locks, then locks are released before rendering; no user pointer escapes.
Status is constant-size, detail uses the ID index and listing inspects at most
the requested page. Account result bodies are capped at 256 KiB, further bounded
by gateway response/working-memory allowances and deadlines.

Operation failures have a nonzero node result code and a small body such as
`{"error":{"code":"busy"}}`; the outer gateway `error` remains null. Codes are
`invalid_request`, `not_found`, `invalid_cursor`, `stale_cursor`, `busy`, `timeout`,
`record_too_large`, `response_too_large` and `invalid_record_encoding`, as
applicable. Gateway authentication, permission, timeout and encoded-envelope
errors retain the [APIServer](APIServer.mdx) contract. Retries and restarting a
stale traversal are caller-controlled.

## User Database Performance

- SHA-256 is the canonical plaintext-password lookup key. A password lookup
  derives SHA-256 once and resolves through the SHA-256 hash index; there is no
  fallback scan over the user table, so both hits and misses are average O(1).
  The exact plaintext comparison after an index hit is the authoritative,
  collision-safe check.
- All keyed lookups (SHA-224, SHA-256, UUID, WireGuard public key, durable id,
  non-empty name) are average O(1); WireGuard Allowed-IP address lookup and
  range-overlap detection are O(log M) through an ordered interval index.
- Accounting retains only the last sequence/digest per configured client; synchronization builds one bounded page at a time.
- Read-only request messages (`Ping`, credential lookups and `GetUsersPage`) share the server state read lock and
  may execute concurrently. Authentication, user mutations and statistics mutations take the state write lock for
  the whole envelope. Mixed envelopes use the strongest lock required by their module descriptors.

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
