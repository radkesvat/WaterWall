<!--
Documentation version: 158
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/UserController.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/UserController.mdx, and all files must keep the same documentation version.
-->

# UserController Node

`UserController` is a middle node for stream or datagram normal lines that enforces per-user limits for traffic-serving chains.

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

In both layouts the per-peer line first passes through unmanaged (no user yet). A custom authenticating integration can record a user with `lineAddUser()` and call the
[programmatic promotion API](#programmatic-promotion-api). WireGuardDevice currently uses its configured peers and does
not attach database users; its internal controller therefore remains unmanaged transport plumbing.

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
    "payload-mode": "stream",
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

- `payload-mode` `(string, required for manual instances)`
  Exactly `"stream"`, `"datagram"`, or `"dest_context->protocol"`. The last option reads TCP/UDP destination metadata once
  during Init. Internal creators bind a metadata resolver instead; conflicting or missing sources are rejected.

- `verbose` `(optional boolean, default: false)`
  Reserved for additional debug logging.

- `sweep-interval-ms` `(optional integer, default: 1000)`
  How often each worker checks open managed lines for disabled, expired, removed, or over-quota users that have gone
  idle and are not currently sending payloads.

`UserController` does not enforce live `devices` occupancy. Stored/exported device limits and diagnostic device
gauges remain available; they do not provide a live device reservation limit.

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
  Each delivery's actual bytes are passed at handoff to AuthenticationClient, which applies its `traffic-multiplier` once and advances
  cumulative charged upload/download counters. When the quota is reached, new
  connections are rejected and already-open connections are closed. Quota is charged at onward handoff, independently
  of bandwidth enforcement.

- `enabled`
  Disabled users (`enabled: false`) may not open new connections and their existing connections are closed. The node
  never writes the `enabled` field; it only reads it.

When any of these conditions causes a rejection or a close, a warning is logged. `UserController` never modifies user
configuration (passwords, limits, expiry, enabled state); it only updates process-local runtime usage and the synced
cumulative traffic counters.

New managed lines use AuthenticationClient cached-admission availability. Existing managed lines keep accounting,
payload expiry checks, idle sweeps and reservation release during ordinary outages or explicit credential rejection.
Cached quotas and reservations are local; multiple disconnected clients may overshoot aggregate quotas. Relative
expiry starts with the first positive measured arrival, even while duration is initially zero; enabling duration
later uses that retained age. Explicit duration and absolute-date edits recompute their components independently.

## Bandwidth And Payload Framing

`limit.bandwidth.u` / `up` and `.d` / `down` are actual logical bytes per second. Zero means unlimited;
the full unsigned 64-bit range is supported. One user's upload and download allowances are independent and shared
by every connection, controller and worker using the same `AuthenticationClient` instance. Other users and other
client instances have independent allowances. This is local enforcement, without coordination between machines.
`traffic-multiplier` changes charged quota bytes only; it never changes rates, bursts, queue sizes or clocks.

For finite rate `R`, ordinary burst capacity is `max(1, ceil(R / 10))` bytes: approximately 100 ms, with a one-byte
minimum at very low rates. Contending eligible queues receive bounded FIFO turns. A whole datagram can hold its turn
while earning credit; fairness does not promise equal latency. Streams retain excess bytes in FIFO order and may split a delivery. Datagrams remain whole and ordered,
including empty datagrams, which consume no rate or quota. A datagram larger than ordinary burst capacity earns its
complete credit before release, even at 1 byte/s; the instantaneous burst has a one-datagram exception. Idle time before
that head became eligible supplies only ordinary burst credit. Canceling or pausing the head releases its turn and
clamps transferable credit to ordinary capacity. Payloads over 65,535 bytes are refused in datagram mode; smaller
protocol-specific limits still apply.

Retained data, prepared fragments and queue entries share these hard resource limits in both directions combined:

| Scope | Logical bytes | Allocation charge | Buffers | Queued direction tickets |
| --- | ---: | ---: | ---: | ---: |
| One managed line | 1 MiB | 2 MiB | 256 | 2 |
| One user in one AuthenticationClient | 4 MiB | 8 MiB | 1024 | 1024 |
| One AuthenticationClient | 64 MiB | 128 MiB | 16384 | 16384 |

These are resource ceilings, not configurable bandwidth rates. Stream admission refusal closes the affected line and
discards retained bytes. Datagram overflow drops only the newly refused datagram; accepted FIFO entries survive.
Required timer or continuation refusal closes the affected line in either mode. Dropped or discarded data is never charged.
Consumer Pause stops that direction's drain and fair-turn eligibility. Resume arranges progress before notifying the
producer. For streams, local shaping pressure and external consumer pressure are independent holds. Datagram backlog
alone never sends producer Pause/Resume: UDP producers may drop arrivals while paused, before this node's queue is full.
Datagrams continue entering the bounded queue while waiting for rate credit; explicit external consumer Pause/Resume
still applies and is propagated to the producer.

First positive measured arrival starts first-use expiry and reporting before queueing, including offline and discounted
traffic; zero length alone does not start use. Quota is charged exactly once, with the multiplier, immediately before
Payload ownership is handed onward. The final permitted chunk is handed off once even if it exhausts or crosses quota,
then the still-live line closes. An already exhausted user receives no further grant. Handoff does not confirm socket delivery.

Configuration refresh preserves same-ID bucket credit, fractional refill, timestamps and queue identity, including password
replacement. Rate changes settle old-rate credit first and clamp it to the new capacity; unchanged refresh adds no burst.
Finite-to-unlimited changes preserve the queued FIFO. Unlimited-to-finite initializes one ordinary burst. Existing managed
lines keep cached enforcement through ordinary authentication-client outages or credential rejection.

Manual instances require an explicit `payload-mode`, even when current users are unlimited:

| Value | Payload handling |
| --- | --- |
| `stream` | Bytes may be split across deliveries. |
| `datagram` | Each payload remains one whole datagram. |
| `dest_context->protocol` | Read the destination protocol once during Init: exactly TCP selects stream; exactly UDP selects datagram. |

Destination-context mode rejects the line if the protocol is missing, ambiguous or unsupported. Use it only when the
destination protocol is available before Init and describes the payload at this node's position. A transport conversion
can leave UDP routing metadata on a line carrying decoded stream bytes, so destination detection is never an automatic
fallback for an omitted setting.

Internal creators instead bind `usercontrollerSetPayloadModeResolver(controller, owner, resolver)` immediately after
construction, before preparation. A configured mode and a resolver cannot both be supplied. The pure owner-worker
metadata query runs once in either Init direction; every mode source is resolved and saved before admission or forwarding.
The saved mode also governs later promotion and cannot change with destination metadata.
SOCKS/Trojan/VLESS resolve initialized TCP versus decoded UDP remote-line roles; HTTP fixes stream mode; WireGuard fixes
datagram mode on its normal transport side in either orientation. Packet lines never enter UserController. This binding
does not add WireGuard database-user authentication; its existing unmanaged transport behavior remains.

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

Live enforcement state (connection/IP reservations, directional rate buckets and fair-turn tickets) is stored on the `user_t`
object inside `AuthenticationClient`, in a dedicated process-local `runtime` field that is never serialized or synced to
`AuthenticationServer`. Charged traffic is added to the normal `stats.traffic` counters. The multiplier is configured
on AuthenticationClient, not UserController; physical payload length, bandwidth and speed are unchanged. The client
accounting helper captures first nonzero local traffic, records an immutable first-use estimate, and starts relative expiry immediately, including
offline. The server merges earliest authorized observations; client monotonic age persists across ACK and refresh.
Login, reservation, zero-byte calls and rebasing do not start or restart it. All access goes through id-keyed
`AuthenticationClient` helpers, so `UserController` never holds a raw `user_t` pointer.

During a full users-table refresh (`GetAllUsers`), matching users are found by durable user id and their process-local runtime
connection/IP counters and shaping state are moved to the refreshed user object. Runtime clock evidence, elapsed age and per-direction
fractional charge remainders move with those reservations. New expiry policy is projected separately from canonical
wall/accounting clock metadata; unchanged pulls never extend an existing countdown.

## Lifecycle Behavior

- On `Init` from either side, the node initializes its line state, records the origin direction, resolves and saves the
  payload mode, and reads the current user handle. An unresolved mode rejects even an anonymous line. For an authenticated
  line it atomically checks all limits and reserves a connection slot (and an IP slot).
  On an upstream `Init` (line from `prev`) it forwards `tunnelNextUpStreamInit()` on success and, on rejection, finishes
  the prev side. On a downstream `Init` (line from `next`) it forwards `tunnelPrevDownStreamInit()` on success and, on
  rejection, finishes the next side. In both cases the rejection path destroys its own line state and never opens the
  far side. Lines that carry no user handle at `Init` pass through unmanaged and can be promoted later through the
  [programmatic promotion API](#programmatic-promotion-api).

- On positive payload arrival, it observes first use and checks eligibility before retaining any data. It prepares exact
  delivery, then commits bandwidth and quota immediately before handoff. A final quota-exhausting candidate is forwarded
  once before close; queued or discarded bytes are not charged. First-use reporting remains coalesced and independent of delivery.

- A per-worker sweep timer checks open managed lines even when they are idle, so disabled, expired, removed, or
  over-quota users are cut off without waiting for another payload.

- On `Finish` from either side, it releases the user's reserved connection and IP slot, destroys its own line state, and
  propagates the finish to the opposite side, following Waterwall's directional-finish rule.

## Programmatic Promotion API

For nodes that authenticate a user only after the line is already open (see [Typical Placement](#typical-placement)),
`UserController` exposes a promotion function in its public `interface.h`:

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
- Call it on the line's owner worker (`lineIsOnCurrentWorker(l)`), and only on a normal line that has already traversed
  this `UserController` instance. It retains the payload mode saved during Init. Do not call it on packet lines.
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
- Bandwidth enforcement is provided by UserController itself; no SpeedLimit node is inserted.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `0` bytes |

## Splice support

Unmanaged and unlimited immediate payloads pass through opaquely in both directions. Shaped queues preserve whole datagrams and split streams through `sbufMoveRangeTo()`, including private pipes with ordinary fallback. Prepared output remains budgeted until handoff or discard. Traffic accounting uses logical payload bytes, including resident prefixes, with the existing reversed upload/download mapping for lines started from next. Rejection recycles the still-owned buffer and discards its private-pipe bytes before closing through the existing lifecycle.

Ordinary fallback buffers remain accepted. Splice requires a supported Linux build, `misc.splice` enabled, no packet nodes, and support from every node in the finalized expanded/merged chain. The capability flag does not bypass these checks. No performance improvement is promised without measurement.
