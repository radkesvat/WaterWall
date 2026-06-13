# AuthenticationServer Node

`AuthenticationServer` is a logical chain-end node for user database management.

It does not open sockets or perform direct network I/O. Instead, it keeps a `users_t` database in memory, loads that
database from JSON on startup, periodically writes the current state back to disk, and answers framed logical requests
from `AuthenticationClient`.

## What It Does

- acts as the upstream end of a logical request/response chain
- loads users from `db-path` into an in-memory `users_t`
- falls back to `db-path.backup` if the primary JSON file cannot be loaded
- removes the backup and rewrites the primary database after successful recovery
- periodically saves the in-memory users database
- writes the backup file before writing the primary database on normal saves
- can write hourly, daily, or weekly normal backup snapshots for operator use
- buffers upstream bytes until a full outer request message is available
- supports multiple request frames inside one outer message
- dispatches request frames to internal modules by request type
- sends one downstream response message containing all response frames for the processed request message

Available modules are `Authenticate`, `ping`, `GetUserBySHA256Hex`, `GetUserBySHA256Base64`, `GetUserBySHA256`,
`GetUserByPassword`, `AddNewUser`, `UpdateUser`, `UpdateUserTraficStatsDiff`, `GetAllUsers`, and `PushUserStats`.

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
      "name": "alice",
      "password": "alice-secret",
      "email": "alice@example.com",
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
- one standalone user object containing `password` or `pass`

For object maps, the object key is used as a username hint only when the user object itself has no non-empty `name`.
The saver always rewrites the database in the normalized `{"users": [...]}` form.

### User JSON Structure

A user object must contain a password string. All other fields are optional:

- `password` or `pass` `(required string)`
  Plaintext password used to create the user's password hash lookup keys.

- `name` `(optional string)`
  Human-readable username. User names must be unique when non-empty.

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
- Password-derived hashes are not stored directly in JSON. They are rebuilt from `password` while loading users.
- The SHA-256 password hash is a lookup key. Two users must not share the same password/SHA-256 key.
- AuthenticationClient credentials are not stored in the user database. They live only in `settings.auth-clients`.
- The authoritative in-memory table tracks separate configuration and statistics revisions. These revisions are server
  metadata, not fields inside individual user objects.
- `AddNewUser` rejects duplicate usernames and password-hash conflicts, then saves the file immediately and bumps the
  configuration revision.
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

Every normal save uses a backup-first write:

1. build JSON from the current in-memory `users_t`
2. write that JSON to `db-path.backup`
3. write the same JSON to `db-path`

For example, if `db-path` is `users.json`, the backup path is `users.json.backup`.

## Startup Recovery

Startup follows this order:

1. load and parse `db-path`
2. if that succeeds, use it as the in-memory database
3. if it fails, try `db-path.backup`
4. if the backup loads successfully, use it, remove the backup file, and rewrite `db-path`
5. if both primary and backup fail, node creation fails

Recovery is logged with warning and info messages so the operator can see that the primary file failed, backup recovery
was attempted, and whether recovery completed.

## Logic Explanation

The important mental model is that `AuthenticationServer` owns one authoritative users table, and every authenticated
`AuthenticationClient` session has its own baseline copy of that table. A client may keep a local writable copy for
traffic accounting, but server-side state changes only through validated request handlers. Client-supplied data is never
allowed to replace the authoritative table unless the request type is explicitly a user-management operation.

### Overall AuthenticationServer Logic

At startup, `AuthenticationServer` creates `ts->store.users`, loads the JSON database from `settings.db-path`, and falls
back to `settings.db-path.backup` if the primary file cannot be loaded. If backup recovery succeeds, the recovered
database becomes the in-memory table, the backup file is removed, and the primary database is rewritten in the
normalized `{"users":[...]}` form.

The authoritative server-side users table is `ts->store.users`. It is wrapped in `authenticationserver_users_store_t`,
together with two server metadata revision counters:

- `config_revision`
  Bumped when user configuration or metadata changes, for example `AddNewUser` or `UpdateUser`.
- `stats_revision`
  Bumped when user traffic statistics change, for example `UpdateUserTraficStatsDiff` or `PushUserStats` with a
  non-zero accepted delta.

`ts->store.users` is authoritative because it is the only table loaded from disk, periodically saved to disk, and used
as the merge target for client updates. All mutations that read or write this table run while holding the server
database mutex. This keeps the source of truth on the server, even when many `AuthenticationClient` sessions are active
and reporting usage at the same time.

### AuthenticationClient Handling

`AuthenticationClient` credentials are control-plane credentials, not normal traffic users. They are configured in
`settings.auth-clients`, for example:

```json
{
  "name": "edge-1",
  "secret": "long-random-secret",
  "allow-stats-push": true,
  "allow-user-pull": true,
  "allow-user-write": false,
  "session-idle-timeout-ms": 600000
}
```

An `AuthenticationClient` first sends an `Authenticate` request containing its `name` and `secret`. If the credentials
match a configured auth client, `AuthenticationServer` creates an `authenticationserver_session_t` entry in
`ts->sessions`. The session stores:

- the issued token
- the client name
- permission flags copied from the matching `auth-clients` entry
- the configured idle timeout for that auth client
- the last activity timestamp for this token
- a private `baseline_users` table
- the `baseline_config_revision` and `baseline_stats_revision` that describe that baseline

When the session is created, the server copies the current authoritative users table into `session->baseline_users`.
That copy is the server-side picture of what this specific client is expected to know. Each authenticated client has a
separate baseline copy because each client can serve different traffic and push stats at different times. One client's
baseline must not be reused for another client, otherwise the server could calculate traffic deltas against the wrong
previous state and either lose usage or double-count it.

After authentication, a client can affect only its own session state plus validated changes merged into the authoritative
users table. The session boundary is the server-side isolation mechanism. It lets many clients work independently while
the authoritative merge still happens in one place.

### Session And Token Behavior

The `Authenticate` response returns response type `4` and exactly 64 bytes of token data. The server generates 32 random
bytes with Linux `getrandom()` and encodes them as 64 lowercase hexadecimal bytes. Token generation fails closed if
secure random bytes are unavailable.

After authentication, the token must be sent in the outer request envelope of every request. `Authenticate` is the only
public request type; every other module requires a valid token. This includes `ping`, user pull requests, user write
requests, and statistics sync requests. Rejecting even ping without a valid token prevents unauthenticated clients from
probing server liveness or protocol behavior through this tunnel.

An outer request message is classified by its envelope token before the contained request frames are dispatched. If the
token already identifies an active session, `Authenticate` is rejected inside that message with `already-authenticated`.
This keeps session creation out of authenticated batches and keeps the session pointer for the batch stable. A client
that needs a new token must send `Authenticate` in an unauthenticated message and use the returned token in later
messages.

The server maps a request to a session by comparing the 64-byte envelope token with the tokens stored in `ts->sessions`.
A zero token is never a valid session token. If no matching session exists, dispatch returns `authentication-required`
for non-public modules. If a matching session exists, dispatch checks the module permission requirements before calling
the module handler.

Sessions are in-memory runtime state. They are not persisted across process restarts. Each session has an inactivity
timeout copied from the matching `auth-clients` entry. If that entry does not set `session-idle-timeout-ms`, the session
uses the top-level `settings.session-idle-timeout-ms`, which defaults to 10 minutes.

Every request message with a valid envelope token refreshes the session's last activity timestamp before its frames are
dispatched. This includes lightweight requests such as `ping`, permission-denied requests, and mixed request batches.
A request with no valid session token does not refresh any session.

Worker `0` runs a forever timer every 60000 ms to expire idle sessions. The timer locks the same server database mutex
used by request dispatch, destroys each expired session's baseline table and token, and compacts `ts->sessions`.
Because dispatch and expiry use the same mutex, a session cannot be destroyed while another worker is using that
session pointer for an authenticated request.

After a session expires, its token is invalid. `AuthenticationClient` must reauthenticate if a request receives
`authentication-required`, if the connection is reset, if the server restarts, or if the token has been idle longer than
its configured timeout.

### User Table Synchronization Logic

The `AuthenticationClient` synchronization flow is:

1. Authenticate and store the returned token.
2. Pull the full users table with `GetAllUsers`.
3. Keep a local client-side users table based on that pulled table.
4. Give traffic-serving nodes, such as `Socks5Server`, pointers or handles into the local table.
5. Let those nodes update runtime usage fields locally while serving traffic.
6. Periodically push changed traffic-stat hints back to AuthenticationServer with `PushUserStats`.
7. Pull the full users table again when the server reports that the client baseline is stale.

The client-side table is intentionally writable by local traffic-serving code for runtime statistics. For example, a
`Socks5Server` node can increment `stats.traffic.up` and `stats.traffic.down` on the user object it received from
`AuthenticationClient`. It must not change passwords, password hashes, identity fields, limits, enabled state, expiry
fields, notes, or other user metadata through that pointer. Server-side stats sync accepts only traffic-stat deltas; it
does not accept arbitrary client-side user metadata changes.

The practical sync interval is expected to be around every 5 minutes, but that timing belongs in AuthenticationClient.
AuthenticationServer simply accepts valid `PushUserStats` requests whenever they arrive.

`GetAllUsers` is the full-table refresh operation. On success, it returns the authoritative users table and replaces
`session->baseline_users` with that returned table. It also updates the session's baseline revisions to the current
server revisions. This is the only normal sync path that replaces a session baseline with a full table copy.

`PushUserStats` is the partial traffic-stat merge operation. When it arrives, the server treats the request body as a
list of traffic-stat hints, not as a replacement users table. Each hint is a user-shaped JSON object, but the server
reads only:

- `password` or `pass`
  Used only to derive the SHA-256 password lookup key.
- `stats.traffic.up` or `stats.traffic.u`
  Optional current upload counter for this client.
- `stats.traffic.down` or `stats.traffic.d`
  Optional current download counter for this client.

Other fields in a hint are ignored. They are not required, validated, merged, copied into `session->baseline_users`, or
copied into `ts->store.users`. A hint must contain at least one traffic counter. The request may contain only users that
changed since the last push; omitted users leave this session baseline unchanged.

For each pushed hint, the server compares the present counters against `session->baseline_users`, using the user's
SHA-256 password hash as the stable lookup key:

- The user must exist in the session baseline.
- The user must still exist in `ts->store.users`.
- Each present traffic counter must be greater than or equal to the matching baseline counter.
- The accepted delta for each present counter is `client_counter - baseline_counter`.

Only positive or zero deltas are accepted. Backwards counters are rejected because allowing subtraction would let a
client erase usage. Unknown users are rejected because a stats push is not a user-management operation. Duplicate user
hints in one request are rejected so one message cannot advance the same baseline twice. This is the main safety rule:
`AuthenticationClient` may report usage, but it may not rewrite users through the stats sync path.

After the deltas are calculated, the server applies them to `ts->store.users` using saturating counter behavior and
advances only the matching traffic counters in this session's baseline. It does not replace the session baseline with
the pushed payload. If any non-zero delta was applied, the server increments `stats_revision`.

If the session baseline was already current before the push, the session's baseline revisions are advanced to the
latest server revisions. If another client or management request changed the authoritative table first, the push can
still succeed, but the session remains stale and the response reports `needs-pull: true`. The client must then call
`GetAllUsers` to refresh its local table.

`PushUserStats` never blindly copies the full updated authoritative table back into the session after a stats push. It
updates only the per-user traffic counters that were present in the request. A full authoritative-table copy into the
session happens only when the client pulls with `GetAllUsers`. This keeps stats merging narrow and makes the client
explicitly refresh when the response says its session is stale.

Revision state is store-level metadata, not per-user metadata. `user_t` does not contain a per-user sync field.
Configuration changes increment `config_revision`; accepted stats changes increment `stats_revision`. `GetAllUsers`
refreshes the session baseline to the returned authoritative table and its revisions.

### Communication Protocol

The outer request envelope is:

- 4-byte body size
- 64-byte authentication token
- one or more request frames

The token is ignored only for `Authenticate` in unauthenticated messages. All other requests use the token to find the
session and enforce permissions. If the token already identifies a session, `Authenticate` is rejected for that message.
The request frames themselves keep the existing frame format: request type, correlation ID, request data length, and
request data bytes.

The outer response envelope is:

- 4-byte body size
- 8-byte `config_revision`
- 8-byte `stats_revision`
- one or more response frames

For a successful stats sync, the `PushUserStats` response body also includes a compact JSON status object with
`config-revision`, `stats-revision`, and `needs-pull`. `AuthenticationClient` compares the returned revisions with its
local table metadata and pulls the latest full users table with `GetAllUsers` when refresh is required.

The refresh decision is revision-based:

- if `server_config_revision != local_config_revision`, pull the full table
- if `server_stats_revision != local_stats_revision` and the client needs an exact current global stats view, pull the
  full table
- if `needs-pull` is true after `PushUserStats`, pull the full table

This split lets the client distinguish user configuration changes from pure usage changes.

### User And Permission Model

Normal users are the accounts authenticated for traffic usage. `AuthenticationClient` credentials and management rights
are configured separately under `settings.auth-clients`. `user_t` does not carry management permissions for this
protocol.

Permission checks are session permissions, not user permissions:

- `allow-user-pull`
  Allows pulling users with `GetAllUsers` and user lookup modules.
- `allow-stats-push`
  Allows pushing usage through `PushUserStats` and `UpdateUserTraficStatsDiff`.
- `allow-user-write`
  Allows user management operations such as `AddNewUser` and `UpdateUser`.

This keeps infrastructure credentials out of the normal users database. It also avoids giving a normal proxy user the
ability to manage other users just because that user object was loaded into AuthenticationClient.

Normal traffic-serving users can accumulate local usage stats. They must not be allowed to change
their own password, password hashes, limits, enabled state, expiration fields, or other users through the stats path.
Those changes belong to authenticated management requests guarded by explicit write permission.

### Integration With Other Nodes

Other nodes should not communicate directly with AuthenticationServer. AuthenticationServer is the upstream authority,
and AuthenticationClient is the frontend used by traffic-serving nodes such as `Socks5Server`.

`AuthenticationClient` exposes handles or singleton pointers to users in its local users table. Other nodes may use
those handles to:

- read user configuration needed for admission decisions, such as enabled state, limits, expiry, and usage
- update local runtime statistics, especially traffic upload/download counters
- update transient local counters needed for enforcement, such as active connection counts, if AuthenticationClient
  decides those are part of its local runtime model

Other nodes should not use those handles to:

- change passwords or password hashes
- add or remove users
- rewrite limits, expiry, enabled state, notes, email, or identity fields
- send AuthenticationServer protocol frames directly

All server communication should go through AuthenticationClient. That keeps token handling, session ownership,
baseline tracking, pull decisions, and stats pushing in one component. Traffic-serving nodes only need to report usage
by mutating the local client-side user table; AuthenticationClient later batches those changes into `PushUserStats`.

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

The `Authenticate` module expects request data containing a JSON object with `name` and `secret` strings:

```json
{"name":"edge-1","secret":"long-random-secret"}
```

If the credentials match an entry in `settings.auth-clients`, the server creates a session, stores a baseline copy of
the current authoritative users table for that session, and returns response type `4` with a 64-byte session token. The
token must be included in the request envelope for later requests.

If credentials are malformed or do not match, it returns an error response frame with the same correlation ID. If the
outer request message already carries a valid session token, `Authenticate` is not dispatched and the response data is
`already-authenticated`.

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

### GetUserByPassword Module

The `GetUserByPassword` module expects request data containing the plaintext password bytes without a trailing NUL.
The payload must be non-empty and must not contain embedded NUL bytes.

If a user with that password exists, the module returns response type `2` and response data containing the full
serialized user JSON object.

If the password payload is malformed or no user matches the password, it returns an error response frame with the same
correlation ID.

### AddNewUser Module

The `AddNewUser` module expects request data containing a JSON object for one user, using the same user format accepted
by `userCreateFromJson()`.

The module validates that the payload is parseable JSON, that it is a user object, that the user can be created, and
that the new user's name and password hashes do not conflict with existing users. If validation passes, the user is
added to the in-memory database and the users file is saved immediately with the normal backup-first save behavior.
If that immediate save fails, the module attempts to roll back the in-memory add and returns a save error.

On success it returns response type `0` and response data equal to `user-added`.

If validation or saving fails, it returns an error response frame with the same correlation ID. If the file save fails
after the in-memory add succeeds, the module attempts to remove that user from memory and returns
`database-save-failed`.

### UpdateUser Module

The `UpdateUser` module expects request data containing a full user JSON object in the same format exported by
`userToJson()`. The password field is used only to find the existing user by its SHA-256 password hash; password and
password-hash values are not updated by this module because they are database lookup keys.

If the user exists, the module updates the mutable user fields in memory, including name, email, notes, group ID,
enabled state, limits, time information, stats, and record-stat interval. It does not trigger an immediate database
file save; the normal periodic save timer is still responsible for persisting in-memory state later.

On success it returns response type `0` and response data equal to `user-updated`.

If the JSON is malformed, the user does not exist, or the update would create a conflicting user name, it returns an
error response frame with the same correlation ID.

### UpdateUserTraficStatsDiff Module

The `UpdateUserTraficStatsDiff` module expects request data containing a full user JSON object. The password field is
used only to find the existing user by its SHA-256 password hash.

If the user exists, the module reads `stats.traffic.up` and `stats.traffic.down` from the supplied JSON and adds those
values to the existing user's traffic counters. No other user fields are updated. The add operation uses the same
saturating counter behavior as `userAddTraffic()`.

This operation does not trigger an immediate database file save; the normal periodic save timer is still responsible
for persisting in-memory state later.

On success it returns response type `0` and response data equal to `user-traffic-stats-updated`.

If the JSON is malformed or the user does not exist, it returns an error response frame with the same correlation ID.

### GetAllUsers Module

The `GetAllUsers` module expects an empty request payload.

On success it returns response type `3` and response data containing the normalized users database JSON from
`usersToJson()`. This is the same shape written to disk by normal saves:

```json
{"users":[...]}
```

On success the session baseline is replaced with the returned table and the current server revisions.

If the request contains unexpected data, or if exporting/serializing the in-memory database fails, it returns an error
response frame with the same correlation ID.

### PushUserStats Module

The `PushUserStats` module expects request data containing one or more partial user stats hints. The accepted outer
layouts are:

- an array of hint objects
- an object with a `users` array of hint objects
- an object map whose values are hint objects
- one standalone hint object

Each hint object must contain `password` or `pass`, and must contain at least one of `stats.traffic.up`,
`stats.traffic.u`, `stats.traffic.down`, or `stats.traffic.d`. The upload/download values may be JSON safe integers or
decimal strings. All other fields are ignored, even if they look like user configuration fields.

The pushed hints must reference only users that exist in both the session baseline and the authoritative table. If any
present traffic counter is lower than the session baseline counter, the request is rejected to avoid subtracting usage.
Duplicate hints for the same password/SHA-256 key in one request are rejected.

After a successful merge, only the pushed traffic counters are advanced in the session baseline. Omitted users and
omitted upload/download counters remain unchanged in that session baseline. If the session was already current before
the push, its baseline revisions are advanced to the latest server revisions. If another client changed the
authoritative table first, the response still succeeds but reports `needs-pull: true`, so `AuthenticationClient` can call
`GetAllUsers` and refresh its local copy.

On success it returns response type `0` and response data containing a compact JSON status object:

```json
{"status":"stats-updated","applied-deltas":2,"needs-pull":false,"config-revision":1,"stats-revision":3}
```

If the JSON is malformed, references unknown users, or contains backwards counters, it returns an error response frame
with the same correlation ID.

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
- The current queued response limit is 16 MiB.
- This node does not require left padding and does not prepend in-place.
- This node is not a packet tunnel and does not use packet-line semantics.
