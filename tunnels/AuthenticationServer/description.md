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
`GetUserByPassword`, and `AddNewUser`.

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

Accepted JSON layouts are the layouts supported by `usersFeedJson()`, including:

- a users array
- an object containing a `users` array
- an object map of username to user object
- a single user object with `password` or `pass`

Saved databases are written as an object containing a `users` array.

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

Upstream payload bytes are buffered as a stream. The outer message framing is:

- 4-byte unsigned big-endian message payload size
- message payload bytes

The message payload contains one or more request frames:

- 1-byte request type
- 4-byte (32-bit) correlation ID
- 4-byte unsigned big-endian request data length
- request data bytes

Each request frame is validated before dispatch. If the outer message payload is empty, contains trailing bytes smaller
than a request header, or declares request data that is not fully present inside the message payload,
`AuthenticationServer` logs a warning and closes the logical connection safely.

Each module returns a response frame:

- 1-byte response type
- 4-byte (32-bit) correlation ID copied from the request
- 4-byte unsigned big-endian response data length
- response data bytes

After all request frames in one message are processed, the server combines all response frames into a single response
payload and sends it with the same outer framing:

- 4-byte unsigned big-endian response payload size
- response frame bytes

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

Current response types:

- `0`: ok
- `1`: `pong`
- `2`: user
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
