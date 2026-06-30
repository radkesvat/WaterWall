<!--
Documentation version: 108
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/UserController.mdx, and both files must keep the same documentation version.
-->

# UserController Node

`UserController` is a middle (stream) node that enforces per-user limits for traffic-serving chains.

It does not open sockets or perform protocol parsing. It sits behind a node that authenticates users (such as
`Socks5Server`) and in front of the outbound side of the chain (such as `TcpConnector`). For every authenticated line
it admits or rejects new connections, accounts traffic, and closes connections that are no longer allowed.

## Typical Placement

`Socks5Server` creates and inserts an internal `UserController` automatically in authenticated mode, so a SOCKS5 chain
should normally be configured without a visible `UserController` node:

```text
TcpListener <--> Socks5Server <--> TcpConnector
```

Manual placement is still useful for other tunnels that call `lineAddUser()` themselves.

`UserController` must be placed upstream (next) of a node that records the authenticated `user_handle_t` on the line with
`lineAddUser()`. It reads the current handle with `lineGetCurrentUser()` and resolves it through the configured
`AuthenticationClient` node. Lines without a valid user handle (for example a `Socks5Server` in `no-auth` mode) are
passed through without enforcement.

Some nodes authenticate the user only *after* the line is already open, and their next side carries packet lines (one
per worker) rather than per-user lines, so they cannot place a `UserController` after themselves the way `Socks5Server`
or `TrojanServer` do. A `WireGuardDevice` doing database-backed peer authentication is the motivating example; it places
the `UserController` on its own side that still carries per-peer lines. Depending on which adapter is the chain head,
that per-peer line is initiated from either side of the `UserController`:

```text
UdpStatelessSocket -> UserController -> WireGuardDevice -> TunDevice   (line starts from prev)
TunDevice -> WireGuardDevice -> UserController -> UdpStatelessSocket   (line starts from next)
```

In both layouts the per-peer line first passes through unmanaged (no user yet). Once `WireGuardDevice` authenticates the
peer it records the user with `lineAddUser()` and calls the [programmatic promotion API](#programmatic-promotion-api) to
apply that user's limits on demand.

`UserController` is bidirectional: it works whether the line is initiated from its `prev` side (an upstream `Init`) or
its `next` side (a downstream `Init`), and it records that origin per line. The origin matters for traffic accounting —
see [Direction Awareness](#direction-awareness-upload-vs-download).

`UserController` does not open sockets; it requires both a `prev` and a `next` node.

## Configuration Example

```json
{
  "name": "user-controller",
  "type": "UserController",
  "settings": {
    "auth-client-node-name": "auth-client",
    "sweep-interval-ms": 1000,
    "verbose": false
  }
}
```

`auth-client` must be a configured `AuthenticationClient` node in the same config file. `UserController` only finds and
uses that node instance; it does not create an authentication client.

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"UserController"`.

### `settings`

- `auth-client-node-name` `(string, required)`
  Name of an existing `AuthenticationClient` node in the same config file. It must point to an `AuthenticationClient`,
  not to `UserController` itself.

- `verbose` `(optional boolean, default: false)`
  Reserved for additional debug logging.

- `sweep-interval-ms` `(optional integer, default: 1000)`
  How often each worker checks open managed lines for disabled, expired, removed, or over-quota users that have gone
  idle and are not currently sending payloads.

## Enforced Limits

`UserController` reads each user's `limit` block from the local `AuthenticationClient` users table. A limit of `0`
(or a missing field) means unlimited. The following limits are enforced:

- `connections-out`
  Maximum number of simultaneous outbound connections (lines) the user may hold. `connections-in` is intentionally
  ignored; both fields conceptually mean "line count", and only the outbound count is tracked. When the limit is
  reached, the next connection is rejected.

- `ips`
  Maximum number of distinct source IP addresses the user may use at the same time. With `ips: 1`, a second device
  connecting from a different IP is rejected while the first IP still has an open connection. A new connection from an
  already-counted IP is always allowed.

- `time`
  Expired users (`expire-at-ms`, or `expire-after-first-usage-ms` after first usage) may not open new connections and
  their existing connections are closed.

- `traffic` (`up` / `down` / `total`)
  The user's cumulative uploaded/downloaded byte counters are advanced on every payload. When the quota is reached, new
  connections are rejected and already-open connections are closed. (This is the data-volume quota, not a bytes-per-second
  speed limit; `bandwidth` speed limiting is not handled by this node.)

- `enabled`
  Disabled users (`enabled: false`) may not open new connections and their existing connections are closed. The node
  never writes the `enabled` field; it only reads it.

When any of these conditions causes a rejection or a close, a warning is logged. `UserController` never modifies user
configuration (passwords, limits, expiry, enabled state); it only updates process-local runtime usage and the synced
cumulative traffic counters.

## Direction Awareness (Upload vs Download)

`UserController` records, per line, which side the line was initiated from, and uses it to map traffic to the user's
upload and download counters correctly. "Upload" means traffic leaving the user toward the far side; "download" means
traffic arriving at the user. The user always sits on the side the line started from.

| Line origin | Initiated by | Upstream payload counts as | Downstream payload counts as |
|---|---|---|---|
| From `prev` (upstream `Init`) | a head/prev adapter (e.g. `UdpStatelessSocket` at the front) | upload | download |
| From `next` (downstream `Init`) | a tail/next adapter (e.g. `UdpStatelessSocket` at the back) | download | upload |

The forward row is the common case (`Socks5Server`, `TrojanServer`, `VlessServer`). The reverse row happens when the
user-facing adapter is the chain tail, as in `TunDevice -> WireGuardDevice -> UserController -> UdpStatelessSocket`:
there the user's packets arrive on the `next` side, so downstream payload is the user's upload. Quota enforcement is
otherwise identical in both directions.

## Where Limit State Lives

Live enforcement state (current outbound connection count and the set of in-use source IPs) is stored on the `user_t`
object inside `AuthenticationClient`, in a dedicated process-local `runtime` field that is never serialized or synced to
`AuthenticationServer`. Cumulative traffic is added to the normal `stats.traffic` counters. `UserController` never creates
or pushes `first-usage-at-ms`; the server owns that timestamp and returns enough server-time metadata for
`AuthenticationClient` to compute a process-local expiry deadline. All access goes through id-keyed
`AuthenticationClient` helpers, so `UserController` never holds a raw `user_t` pointer.

During a full users-table refresh (`GetAllUsers`), matching users are found by durable user id and their process-local runtime
connection/IP counters are moved to the refreshed user object. Expiry state is recalculated from the refreshed server
table and the response's server-time metadata.

## Lifecycle Behavior

- On `Init` from either side, the node initializes its line state, records the origin direction, and reads the current
  user handle. For an authenticated line it atomically checks all limits and reserves a connection slot (and an IP slot).
  On an upstream `Init` (line from `prev`) it forwards `tunnelNextUpStreamInit()` on success and, on rejection, finishes
  the prev side. On a downstream `Init` (line from `next`) it forwards `tunnelPrevDownStreamInit()` on success and, on
  rejection, finishes the next side. In both cases the rejection path destroys its own line state and never opens the
  far side. Lines that carry no user handle at `Init` pass through unmanaged and can be promoted later through the
  [programmatic promotion API](#programmatic-promotion-api).

- On upstream payload (upload) and downstream payload (download), it adds the byte count to the user's traffic counters.
  The AuthClient accounting helper internally asks for one coalesced early `PushUserStats` attempt when the first non-zero
  local traffic arrives for a user whose cache still lacks `first-usage-at-ms`. If the user is now over quota, expired, or
  disabled, it recycles the buffer and tears the line down in both directions.

- A per-worker sweep timer checks open managed lines even when they are idle, so disabled, expired, removed, or
  over-quota users are cut off without waiting for another payload.

- On `Finish` from either side, it releases the user's reserved connection and IP slot, destroys its own line state, and
  propagates the finish to the opposite side, following Waterwall's directional-finish rule.

## Programmatic Promotion API

For nodes that authenticate a user only after the line is already open (see [Typical Placement](#typical-placement)),
`UserController` exposes one function in its public `interface.h`:

```c
WW_EXPORT user_admission_result_t usercontrollerTunnelTryManageLine(tunnel_t *t, line_t *l);
```

It runs the same admission as upstream `Init` — checking every limit and reserving a connection + IP slot — but on
demand. A node that wants to use it:

1. Keeps a pointer to its `UserController` instance (created the same way `Socks5Server` builds its internal
   `UserController`, via `nodeUserControllerGet()` + `createHandle`).
2. Authenticates the peer and records the user on the line with `lineAddUser()`.
3. Calls `usercontrollerTunnelTryManageLine(user_controller_instance, line)`.

Return values:

| Result | Meaning |
| --- | --- |
| `kUserAdmissionOk` | The line is now managed (admitted), was already managed (idempotent), or carries no user and was left as an unmanaged passthrough. Proceed. |
| any other `kUserAdmission*` | The user was rejected (disabled, expired, over quota, connection limit, or IP limit). The line is left **unmanaged and untouched**. |

Contract:

- On any non-OK result the function never sends a finish and never destroys line state. The **caller owns the
  rejection** and must close/drop the line itself; it must not treat a rejected line as admitted. A non-OK call reserves
  nothing, so retrying later is safe.
- Call it on the line's owner worker (`lineGetWID(l) == getWID()`), and only on a normal line that has already traversed
  this `UserController` instance. Do not call it on packet lines.
- Once a line is managed this way, traffic accounting, the idle sweep, and `Finish`-time slot release all apply exactly
  as they do for a line admitted at `Init`; no extra teardown wiring is needed on the caller side.

Example sketch (inside the authenticating node, after a successful handshake on `line`):

```c
lineAddUser(line, &resolved_handle, username, password);

user_admission_result_t admission = usercontrollerTunnelTryManageLine(ts->user_controller_tunnel, line);
if (admission != kUserAdmissionOk)
{
    // limits exceeded (for example IP limit): reject this peer / close the line here.
    return;
}
// admitted: continue bringing the peer up.
```

## Notes And Caveats

- This node requires `AuthenticationClient`; node creation fails if `auth-client-node-name` is missing or wrong.
- This node does not require left padding and does not prepend in-place.
- This node is not a packet tunnel and does not use packet-line semantics.
- Speed (bytes-per-second / `bandwidth`) limiting is out of scope; use `SpeedLimit` for that.
