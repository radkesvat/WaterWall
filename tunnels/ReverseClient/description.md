<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/reverse-client.mdx, and both files must keep the same documentation version.
-->

# ReverseClient Node

`ReverseClient` keeps a pool of pre-opened reverse connections toward a remote `ReverseServer`. When one of those waiting reverse connections starts carrying real traffic, `ReverseClient` creates a local-facing line for the previous node and forwards traffic through that reverse channel.

In practice, this node is used on the client side of a reverse tunnel setup.

## What It Does

- Pre-creates outbound reverse connections through the next node.
- Keeps a minimum number of spare, ready-to-use reverse connections per worker.
- Sends an internal handshake on each spare connection.
- Waits until a reverse connection is actually assigned traffic.
- Once assigned, opens a line toward the previous node and forwards payload in both directions.
- Replenishes the spare reverse connection pool whenever a connection is consumed or closed.

This node is neither a pure chain head nor a pure chain end. It behaves like a local inbound source for the previous node, while it also consumes an outbound path through the next node.

## Typical Placement

A common setup is:

- `ReverseClient` on the machine that cannot accept direct inbound traffic
- a `Bridge` near `ReverseClient` to attach the reverse side to another local chain segment
- some outbound transport after it, such as TCP/TLS/HTTP tunnels, leading to the remote side
- `ReverseServer` on the reachable side of that transport
- a paired `Bridge` near `ReverseServer` to attach the reverse side to the service-facing chain

`ReverseClient` expects the next side of the chain to be able to create and carry outbound connections to the remote `ReverseServer`. In most practical layouts, the local-facing side of the design is connected with a paired `Bridge` node.

## Configuration Example

```json
{
  "name": "reverse-client",
  "type": "ReverseClient",
  "settings": {
    "minimum-unused": 16,
    "reverse-secret-length": 640,
    "reverse-secret": "shared-secret"
  },
  "next": "outbound-chain-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"ReverseClient"`.

- `next` `(string)`
  The next node used to create the outbound reverse connections.

### `settings`

The implementation works with an empty `settings` object. Optional fields tune
the spare connection pool and the reverse-link handshake signature.

## Optional `settings` Fields

- `minimum-unused` `(integer)`
  Minimum number of spare reverse connections that this tunnel tries to keep available.

  Default: `workers * 4`

  This value must be greater than `0`.

- `reverse-secret-length` `(integer)`
  Overrides the reverse handshake length.

  Default: `640`

  This value must be in range `1` to `1024`.

- `reverse-secret` `(string)`
  Changes the reverse handshake bytes by XORing the default handshake bytes with
  the ASCII bytes of this string repeatedly.

  `ReverseClient`, `ReverseServer`, and any `SniffRouter` reverse route in front
  of them must use the same `reverse-secret-length` and `reverse-secret`.

## Detailed Behavior

### Startup behavior

When the tunnel starts, it asks every worker to create reverse connections until that worker has enough spare capacity. The target spare count is controlled by `minimum-unused`.

The code tracks two per-worker counters:

- connecting reverse connections
- established but still unused reverse connections

If the sum is below the configured minimum, the tunnel schedules more reverse connection attempts.

### How a reverse connection is created

For each spare reverse connection, `ReverseClient` creates two internal lines:

- one line that goes to the next node and carries the real transport
- one paired local-facing line that will later be exposed to the previous node if the reverse connection becomes active

As soon as the outbound side is initialized, `ReverseClient` sends the full
internal handshake in one payload. By default this is `640` bytes of value
`0xFF`. If `reverse-secret` is configured, the default bytes are XORed with the
secret bytes repeatedly. `ReverseServer` uses the same configured handshake to
recognize these spare reverse connections.

### When a spare connection becomes active

A spare reverse connection remains unused until the remote side sends actual payload back through it.

When the first real downstream payload arrives on that reverse connection:

- the connection is removed from the unused pool
- the spare counter is decremented
- a replacement spare connection is scheduled
- the local paired line is initialized toward the previous node
- payload starts flowing between the local line and the reverse channel

This is the key behavior of `ReverseClient`: it turns an already-open outbound reverse connection into a newly exposed local line only when the remote side actually needs it.

### Data flow direction

After pairing:

- Local side to remote side: previous node -> `ReverseClient` -> next node
- Remote side to local side: next node -> `ReverseClient` -> previous node

Pause and resume signals are also forwarded across the paired lines.

### Connection lifecycle and replenishment

`ReverseClient` keeps the pool alive automatically:

- when a spare connection is consumed, it schedules a replacement
- when a paired active connection closes, it schedules a replacement
- when a still-unused connection closes before being paired, it also schedules a replacement

### Starvation timeout

Unused reverse connections are tracked in an idle table.

Current timeout:

- about `30 seconds` for a spare connection that never becomes paired

If that timeout expires, the spare connection is closed and replaced with a fresh one.

### Establishment semantics

A spare reverse connection counts as established after the next node reports downstream establishment for that outbound line. At that point it becomes part of the unused pool, ready to be assigned later.

## Notes And Caveats

- `reverse-secret-length` and `reverse-secret` must match the peer
  `ReverseServer` and any `SniffRouter` reverse detector in front of it.
- This node relies on an internal handshake format shared with `ReverseServer`.
- Spare reverse connections are created proactively, so this tunnel intentionally keeps some idle outbound connections open.
