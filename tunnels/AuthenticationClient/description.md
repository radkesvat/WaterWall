# AuthenticationClient

`AuthenticationClient` is the frontend side of the Waterwall authentication database protocol. It is a chain-head control
node: when the tunnel starts it creates one internal control `line_t` on worker 0, sends that line upstream to its next
node, authenticates with `AuthenticationServer`, pulls the authoritative users table, and periodically keeps the session
alive and pushes local traffic counters.

It is not a data pass-through tunnel. Other tunnels use its internal API from
`include/AuthenticationClient/interface.h` to read users or add traffic to the local table.

## Expected Chain

Typical client-side chain:

```text
AuthenticationClient -> TcpConnector
```

The connector path should reach an `AuthenticationServer`. The client sends protocol bytes upstream with
`tunnelNextUpStreamPayload()`. Responses come back through the normal downstream direction into
`AuthenticationClient`.

`AuthenticationClient` owns the control line it creates. Because it is the line creator, it is also the only tunnel that
destroys that line.

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

## Settings

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
  "verbose": false
}
```

`ping-interval-ms` sends authenticated `Ping` requests and also retries `Authenticate` while the transport is connected
but not authenticated.

`pull-interval-ms` enables periodic revision checks for `GetAllUsers`. A value of `0` disables timer-driven pulls, but
the client still pulls once after successful authentication and when the server reports `needs-pull`.

`push-interval-ms` enables periodic `PushUserStats`. A value of `0` disables periodic pushes. Other tunnels can still
ask for a push through the internal API.

When pull or push is enabled, one `sync_timer` runs at the shortest enabled pull/push interval. Each sync tick checks
which jobs are due and attempts `PushUserStats` first. `GetAllUsers` is sent when revisions differ, or when the pull
cadence is due and no fresher response has already confirmed that the server and local table revisions match.

`reconnect-interval-ms` controls reconnect delay after the control transport closes. A value of `0` reconnects
immediately on worker 0.

`request-timeout-ms` closes and reconnects the control line if any request stays pending longer than the configured
time. A value of `0` disables pending request timeout checks.

`verbose` enables focused debug logs for the control-line lifecycle, reconnect decisions, timer ticks, and
request/response correlation flow. It does not log secrets, session tokens, passwords, or raw users JSON.

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

When `Authenticate` returns a `Session` response, the 64-byte token becomes the active token for all later requests, and
the client immediately sends `GetAllUsers`.

## Local Users Table

The client keeps one active local users table. It is protected by a tunnel-level `wrwlock_t`.

`GetAllUsers` replacement is atomic from the point of view of other tunnels:

1. The response JSON is parsed into a fresh `users_t`.
2. The fresh table is validated.
3. The active table pointer is swapped under the write side of the rwlock.
4. The generation counter is incremented.
5. The old table is destroyed after the swap.

Readers hold the read side of the same rwlock while copying JSON, copying stats, or updating traffic by SHA-256. This
prevents a user pointer returned by `users_t` from becoming invalid during the operation.

The table is local cache plus local counter accumulation. The server remains the source of truth for full user config.

## Internal API

The internal Waterwall API is exposed through:

```c
#include "AuthenticationClient/interface.h"
```

This is intentionally separate from `api.c`, which is the external program API pattern used by all tunnels.

Other tunnels must not receive or cache raw `user_t *` pointers from `AuthenticationClient`. Instead they use
`user_handle_t` from `ww/objects/user_handle.h`, which contains:

```text
sha256(password)
users_generation
```

The handle is a value identifier, not an owned object. A full users-table replacement increments the generation, so old
handles become stale. Callers can either look up a fresh handle or check with `authenticationclientUserHandleIsLive()`.

Available internal operations:

```c
authenticationclientGetState(t)
authenticationclientIsReady(t)
authenticationclientUsersGeneration(t)
authenticationclientGetUserByPassword(t, password, &handle)
authenticationclientGetUserBySHA256(t, sha256, &handle)
authenticationclientUserHandleIsLive(t, &handle)
authenticationclientUserToJson(t, &handle)
authenticationclientUsersToJson(t)
authenticationclientUserGetStats(t, &handle, &stats)
authenticationclientUserAddTraffic(t, &handle, upload, download)
authenticationclientRequestPull(t)
authenticationclientRequestPush(t)
```

`authenticationclientUserToJson()` and `authenticationclientUsersToJson()` return new `cJSON` objects owned by the
caller. Stats are copied into caller storage. Traffic updates are applied by SHA-256 through `usersAddTrafficBySHA256()`;
the caller never mutates a `user_t` directly.

`authenticationclientRequestPull()` and `authenticationclientRequestPush()` do not create their own lines. If called from
another worker, they queue a worker-0 task that tries to send the request on the current control line. If the client is
stopped, disconnected, unauthenticated, write-paused, or already has that request type in flight, the request is simply
not sent.

## Stats Push

`PushUserStats` is treated as a partial hint update. The client sends only the fields the server needs:

```json
{
  "users": [
    {
      "password": "user-password",
      "stats": {
        "traffic": {
          "up": "12345",
          "down": "67890"
        }
      }
    }
  ]
}
```

Users without traffic counters in the local JSON snapshot are skipped for that push. This keeps push messages focused on
password plus traffic stats. The server compares these counters against the session baseline created by `GetAllUsers` and
applies only deltas.

If the server says `needs-pull: true`, the client requests `GetAllUsers` again to refresh the local cache and server-side
session baseline.

## Timers

All protocol timers live on worker 0, the same worker as the owned control line:

`ping_timer` sends `Ping` while authenticated and retries `Authenticate` while connected but unauthenticated.

`sync_timer` drives both user-table pull and stats push using the shortest enabled pull/push interval. Each tick checks
the independent pull/push cadence, queues `PushUserStats` first when due, then queues `GetAllUsers` when revisions
differ or the pull cadence is due without a fresher equal-revision response.

`reconnect_timer` opens a new control line after downstream transport close.

Timers are deleted from `onWorkerStop` for worker 0, not from `onStop`, because timer deletion must happen on the same
worker event loop that owns the timer.

## Lifecycle And Line Safety

The control line's `AuthenticationClient` line state contains only the downstream response read stream. It is initialized
before `tunnelNextUpStreamInit()` and destroyed before the client propagates an upstream finish or destroys the owned
line.

Downstream `Finish` means the next side closed the transport. The client:

1. Removes the active control-line pointer under the control mutex.
2. Clears session token, authenticated state, in-flight flags, and pending requests.
3. Destroys this tunnel's line state.
4. Destroys the owned line.
5. Schedules reconnect unless the tunnel is stopping.

When the client itself closes the control line, such as during worker-0 shutdown or malformed response handling, it
destroys its local line state first, then sends `tunnelNextUpStreamFinish()`, then destroys the owned line if it is still
alive.

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
