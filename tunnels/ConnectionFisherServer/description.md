<!--
Documentation version: 152
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/ConnectionFisherServer.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/ConnectionFisherServer.mdx, and all files must keep the same documentation version.
-->

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
- the continuing path is published before next Init, and transport `Est` is forwarded promptly once, including synchronous Est from Init
- upstream and downstream `Pause` / `Resume` are forwarded only after the probe has completed

The body coalesced with FISH? and the first post-probe payload retain their FIFO
position across the FISH! reply, onward Init and nested Est callbacks. Temporary
input ordering is bounded to 2 MiB and 1,024 buffers, including the body held across Init. It drains
within the admitted dispatch and does not queue ready data merely for Pause or
Est. The incomplete probe is at most four bytes; a complete probe can include an application body
within the separate 2 MiB limit. Close during Init or Est releases older local input before returning.

## Finish And Safety Behavior

- if the probe is invalid, the tunnel destroys its line state first and then closes both directions
- a real upstream `Finish` destroys local state and only propagates upstream if `next` was already initialized
- a real downstream `Finish` destroys local state and propagates downstream toward `prev`
- if a protocol error occurs before upstream init was sent to `next`, only the previous side is closed because there is no next-side line yet

## Configuration

`ConnectionFisherServer` currently has no settings.

```json
{
  "name": "connection-fisher-server",
  "type": "ConnectionFisherServer",
  "next": "next-node-name"
}
```

## Splice Support and Setup Retirement

Both nodes accept ordinary buffers and private-pipe payloads. Complete deliveries entering handshake
or selection parsing are materialized with `sbufEnsureOrdinary()`; application FIFOs retain buffers
opaquely. A complete five-byte marker can carry up to 2 MiB of following application data. An incomplete
marker retains at most four bytes, and the marker does not consume the application-data allowance.

After setup and FIFO drain, the nodes release their handshake streams and empty queue storage. Ready
payloads pass through without inspection, materialization or the startup backlog limit. The client
keeps the main-to-selected-child mapping needed for payload, pressure and Finish callbacks. Server
backend initialization still waits for the first application payload, so losing candidates create no
backend connection. Neither node requests ordinary reads for the established TCP stream.

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
