# ConnectionFisherClient Node

`ConnectionFisherClient` is a client-side bridge tunnel that fans one incoming Waterwall line out into several simultaneous outbound candidate lines, sends a fixed `5`-byte probe on each candidate, and keeps the first candidate that proves it reached `ConnectionFisherServer`.

It is meant for stream chains. The original line stays on the previous side of the tunnel, while the candidate lines are internal helper lines that only exist toward the next side of the chain.

## What It Does

- reads `settings.simultaneous-tries-perline`
- creates that many child lines on every upstream `Init`
- sends upstream `Init` on every child line immediately
- sends the `5`-byte client probe `FISH?` on every child line
- waits for the `5`-byte server reply `FISH!`
- buffers upstream payload on the original line until one child is validated
- keeps exactly one validated child and closes the rest
- closes the original line if no child validates within `5000 ms`
- closes the original line if any child returns non-handshake bytes before selection

## Intended Placement

A typical client-side chain is:

- `TcpListener -> ConnectionFisherClient -> TcpConnector`

The matching server side is:

- `TcpListener -> ConnectionFisherServer -> ...`

`ConnectionFisherClient` only bridges toward `next`. The original accepted line is never sent to `next` directly.

## Configuration

```json
{
  "name": "connection-fisher-client",
  "type": "ConnectionFisherClient",
  "settings": {
    "simultaneous-tries-perline": 3
  },
  "next": "tcp-connector"
}
```

### `settings`

- `simultaneous-tries-perline` `(integer, default: 2)`
  Number of concurrent child lines created for each incoming line.
  Values smaller than `1` are rejected.

## Lifecycle Notes

- upstream `Init` on the original line allocates per-line bridge state and spawns the child lines
- child lines are initialized before any buffered payload is released
- the original line does not emit downstream `Est` until a child is both validated and transport-established
- upstream payload received before selection is queued in a normal `buffer_queue_t`
- once a winner is selected, queued payload is flushed in order onto that child line

## Finish And Safety Behavior

- if the winner child closes, the original line is closed
- if every child fails before a winner is chosen, the original line is closed
- main-line close destroys main bridge state first, then closes every still-alive child line, then propagates the real downstream finish toward the previous tunnel
- child-line close destroys child protocol state first, closes the next side of that child line, and only then decides whether the main line must also be closed
- every child line holds a positive ref on the main line so child callbacks never dereference a freed main-line pointer

## Important Composition Rule

The child lines created by `ConnectionFisherClient` are internal bridge lines.

- they are valid only toward `next`
- they must never be sent to `prev`
- the original line is valid only toward `prev`

This is why the tunnel manually bridges payload, `Est`, `Pause`, `Resume`, and `Finish` between the winning child and the original line instead of forwarding the original line directly.
