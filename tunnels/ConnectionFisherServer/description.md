# ConnectionFisherServer Node

`ConnectionFisherServer` is the server-side peer for `ConnectionFisherClient`.

It delays upstream `Init` until it has validated the fixed `5`-byte client probe, sends the fixed `5`-byte reply, and only then turns the line into a normal forwarding stream.

## Probe Exchange

- client probe: `FISH?`
- server reply: `FISH!`

Both values are fixed ASCII `5`-byte markers.

## What It Does

- accepts a new line from the previous tunnel without forwarding upstream `Init` yet
- buffers upstream bytes until at least `5` bytes are available
- validates that the first `5` bytes match the client probe
- sends the `5`-byte reply back downstream
- calls `tunnelNextUpStreamInit()` only after the probe is valid
- forwards any buffered bytes after the first `5` upstream once the next side exists
- closes the line if the first `5` bytes do not match the probe

## Intended Placement

A common placement is:

- `TcpListener -> ConnectionFisherServer -> TcpConnector`

or any other server-side stream chain where the first `5` bytes are reserved for the ConnectionFisher probe.

## Lifecycle Notes

- upstream `Init` only initializes local line state
- upstream `Init` is intentionally delayed toward `next`
- downstream `Est` is forwarded only after the probe has completed and the line is in normal forwarding mode
- upstream and downstream `Pause` / `Resume` are forwarded only after the probe has completed

## Finish And Safety Behavior

- if the probe is invalid, the tunnel destroys its line state first and then closes both directions
- if the line closes after upstream init was already sent to `next`, the tunnel propagates the real upstream finish before sending downstream finish toward `prev`
- if the line closes before upstream init was sent to `next`, only the previous side is closed because there is no next-side line yet

## Configuration

`ConnectionFisherServer` currently has no settings.

```json
{
  "name": "connection-fisher-server",
  "type": "ConnectionFisherServer",
  "next": "next-node-name"
}
```
