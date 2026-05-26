# AuthenticationServer Node

`AuthenticationServer` is a logical chain-end node for user database management.

It does not open sockets or perform direct network I/O. Instead, it keeps a `users_t` database in memory, loads that
database from JSON on startup, periodically writes the current state back to disk, and answers framed logical requests
from a future `AuthenticationClient`.

## What It Does

- acts as the upstream end of a logical request/response chain
- loads users from `db-path` into an in-memory `users_t`
- falls back to `db-path.backup` if the primary JSON file cannot be loaded
- removes the backup and rewrites the primary database after successful recovery
- periodically saves the in-memory users database
- writes the backup file before writing the primary database on normal saves
- buffers upstream bytes until a full outer request message is available
- supports multiple request frames inside one outer message
- dispatches request frames to internal modules by request type
- sends one downstream response message containing all response frames for the processed request message

The first implemented modules are `ping`, `GetUserBySHA256Hex`, `GetUserBySHA256Base64`, `GetUserBySHA256`,
`GetUserByPassword`, `AddNewUser`, `UpdateUser`, `UpdateUserTraficStatsDiff`, and `GetAllUsers`.

## Typical Placement

`AuthenticationServer` is intended to be the last node in a logical authentication chain.

Future usage will look like:

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
    "file-save-rate-ms": 10000
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

### Accepted User Database Layouts

`usersFeedJson()` accepts a few input layouts for compatibility:

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

The same time fields are also accepted at the top level of the user object for compatibility. Values are milliseconds
since Unix epoch, except `expire-after-first-usage-ms`, which is a duration after first usage.

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
- Each in-memory user also has a private atomic `sync_index` that starts at `1`. It is not loaded from, or settable by,
  the database JSON. `PullChangesSync` responses include it so clients can track per-user sync state.
- `AddNewUser` rejects duplicate usernames and password-hash conflicts, then saves the file immediately.
- `UpdateUser` uses the supplied password only to find the existing user and deliberately does not change password or
  password hashes. It updates in-memory metadata only and does not force an immediate file save.
- `UpdateUserTraficStatsDiff` uses the supplied password only to find the existing user, then adds only
  `stats.traffic.up/down` as a delta. It does not force an immediate file save.
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

## Request And Response Framing

Upstream payload bytes are buffered as a stream. The request envelope is:

- 4-byte unsigned big-endian body size
- 4-byte unsigned big-endian `last_pull_index`
- request payload bytes

The body size is the number of bytes after the size prefix, so it includes the 4-byte `last_pull_index` plus the
request payload. `last_pull_index` is the latest server index known by the client.

The request payload contains one or more request frames:

- 1-byte request type
- 4-byte (32-bit) correlation ID
- 4-byte unsigned big-endian request data length
- request data bytes

Each request frame is validated before dispatch. If the envelope body is too small for `last_pull_index`, the request
payload is empty, contains trailing bytes smaller than a request header, or declares request data that is not fully
present inside the request payload, `AuthenticationServer` logs a warning and closes the logical connection safely.

Each module returns a response frame:

- 1-byte response type
- 4-byte (32-bit) correlation ID copied from the request
- 4-byte unsigned big-endian response data length
- response data bytes

After all request frames in one message are processed, the server combines all response frames into a single response
payload and sends it with the response envelope:

- 4-byte unsigned big-endian body size
- 4-byte unsigned big-endian `last_server_index`
- response frame bytes

`last_server_index` is the current AuthenticationServer tunnel `server_index`. It starts at `1` on tunnel creation and
increments whenever a user-changing request marks a user dirty. `AddNewUser` and `UpdateUser` mark their affected user
dirty. Read-only requests and `UpdateUserTraficStatsDiff` do not change it.

This keeps the request/response transport extensible for future request types.

## Modules

Modules live under `tunnels/AuthenticationServer/modules/`.

Current request types:

- `1`: `ping`
- `2`: `GetUserBySHA256Hex`
- `3`: `GetUserBySHA256Base64`
- `4`: `GetUserBySHA256`
- `5`: `GetUserByPassword`
- `6`: `AddNewUser`
- `7`: `UpdateUser`
- `8`: `UpdateUserTraficStatsDiff`
- `9`: `GetAllUsers`
- `10`: `PullChangesSync`

Current response types:

- `0`: ok
- `1`: `pong`
- `2`: user
- `3`: users database
- `4`: sync users array
- `255`: error

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

If the request contains unexpected data, or if exporting/serializing the in-memory database fails, it returns an error
response frame with the same correlation ID.

### PullChangesSync Module

The `PullChangesSync` module expects request data containing a minimized JSON array of the users known by the client.
Each entry should contain only:

```json
[
  {
    "password": "alice-secret",
    "sync_index": 1
  }
]
```

`password` identifies the user through the server-side password hash. `sync_index` is the last per-user sync index the
client has for that user. `sync-index` is also accepted as an input alias.

The server compares each server-side user with the client's claimed state. A user is returned when:

- the client did not send that user
- the server-side `sync_index` is greater than the client's `sync_index`
- the client claims a `sync_index` greater than the server-side value, which can happen after a server restart

On success it returns response type `4` and response data containing a JSON array of full user objects that need to be
refreshed by the client. Each returned user includes a `sync_index` field. This `sync_index` is response metadata only;
it is not accepted from normal database JSON and is not written as durable user state.

If the JSON is malformed or any client array entry does not contain a usable `password` and `sync_index`, it returns an
error response frame with the same correlation ID.

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
