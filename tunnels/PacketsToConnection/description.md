<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/PacketsToConnection.mdx, and both files must keep the same documentation version.
-->

# PacketsToConnection

`PacketsToConnection` is a packet-to-transport bridge built on lwIP.

It accepts raw IPv4 packets on the packet side, injects them into lwIP, and exposes the resulting transport flows as normal Waterwall `line_t` connections toward the next tunnel.

## What It Is

This node is for chains that start from packet traffic and then want to enter Waterwall's normal connection-oriented world.

Conceptually:

- packet side -> `PacketsToConnection` -> normal Waterwall service chain
- service-chain responses -> `PacketsToConnection` -> raw IP packets back to the packet side

It is closer to a small in-process transport stack bridge than to a framing adapter.

## What It Is Not

- It is not a TUN device manager.
- It does not create or configure routes or OS policy rules.
- It does not replace `TunDevice`.
- It does not serialize packets onto a stream like `PacketsToStream`.

`TunDevice` owns the real packet adapter side.

`PacketsToConnection` owns the lwIP transport bridge side.

## Current Protocol Support

- IPv4: supported
- TCP: supported
- UDP: supported as per-flow Waterwall lines
- IPv6: not supported
- ICMP: not supported

Unsupported packets are dropped conservatively.

## Flow Model

### Packet ingress

Upstream payload must be a full IPv4 packet.

`PacketsToConnection` does not create one lwIP `netif` per destination IP.

Instead, it keeps a worker-local route context for each packet worker that sends packets into the tunnel. For IPv4, that route context owns one lwIP `netif` with `NETIF_FLAG_PRETEND` enabled.

The destination IP is preserved in the packet and in the lwIP PCB tuple, but it is not used as the key for creating separate route contexts. In the current source, the IPv4 route-context lookup is keyed by packet worker id.

For each worker-local pretend netif:

- TCP gets one pretend wildcard listener on first TCP packet
- UDP gets one pretend wildcard PCB on first UDP packet

The Waterwall lwIP pretend patch lets those wildcard PCBs accept packets for arbitrary destination addresses and ports on the pretend netif while still preserving the original local destination tuple.

### TCP flow creation

When lwIP accepts a TCP connection:

- `PacketsToConnection` creates a real Waterwall line
- fills the line source/destination address context from the TCP tuple
- schedules upstream `Init`
- forwards later payload with upstream `Payload`

Downstream payload from the next tunnel is written back into lwIP with `tcp_write()`.

The TCP listener is not per destination port. It is bound as a pretend listener on the worker-local netif, and accepted TCP PCBs carry the original destination IP and port from the packet.

### UDP flow creation

UDP is tracked per worker-local route context and per 4-tuple:

- source IPv4 address
- destination IPv4 address
- source port
- destination port

When the first datagram for a UDP flow arrives:

- `PacketsToConnection` creates a real Waterwall line for that flow
- fills source/destination address context
- schedules upstream `Init`
- forwards datagrams with upstream `Payload`

Downstream payload from the next tunnel is sent back through the connected UDP PCB, using the original local destination address and port as the packet source.

UDP lines are closed by idle timeout, not by packet half-close semantics.

Like TCP, the initial UDP listener is not per destination port. The pretend UDP path creates or reuses a connected per-flow UDP PCB carrying the original source and destination tuple, and `PacketsToConnection` maps that tuple to a Waterwall line.

## Worker And Lifetime Model

This tunnel sits on a shared packet line on the packet side and creates normal Waterwall lines behind it.

Important internal rules:

- the packet line is not closed during runtime
- packet-line `Init` is a startup/bootstrap event, not a per-flow open
- generated TCP/UDP Waterwall lines are owned by the packet worker that accepted the flow
- lwIP callbacks hand work back to the owning line worker through `lineScheduleTask()` and `lineScheduleTaskWithBuf()`
- delayed UDP idle close runs on the line owner with `lineScheduleDelayedTask()`
- packets emitted back to the packet side use the worker packet line for that packet worker

This keeps line destruction and tunnel state teardown on the normal Waterwall line side instead of relying on ad-hoc cross-worker message ownership.

The internally created TCP/UDP lines are normal connection lines. They are separate from the persistent worker packet line and may be closed and destroyed during normal runtime.

## Finish / Close Behavior

When the network side closes a flow:

- lwIP state is detached first
- this tunnel destroys its own line state
- if upstream `Init` was already sent, upstream `Finish` is propagated
- the internally created line is then destroyed by `PacketsToConnection`

When the next tunnel sends downstream `Finish`:

- `PacketsToConnection` closes the lwIP side
- destroys its own line state
- destroys the internally created line

It does not reflect that downstream `Finish` back toward upstream.

That matches Waterwall's direction rules for internally created lines.

The shared packet line is not destroyed by these flow closes. It remains alive until the tunnel chain is destroyed.

## Pause / Resume

### TCP

TCP backpressure is integrated with Waterwall:

- if lwIP cannot accept all downstream bytes, remaining data is queued
- upstream is paused with `tunnelNextUpStreamPause()`
- lwIP sent callbacks flush the queue
- upstream is resumed with `tunnelNextUpStreamResume()` when writable again

For receive-side backpressure:

- downstream `Pause` stops immediate `tcp_recved()`
- downstream `Resume` releases the deferred receive credit

### UDP

UDP has no true stream backpressure model.

Current behavior:

- downstream `Pause` marks the flow paused
- inbound UDP datagrams received while paused are dropped
- downstream `Resume` clears the paused state

This is intentional and should be treated as a current limitation of the UDP path.

## JSON Settings

`PacketsToConnection` currently supports:

- `udp-idle-timeout-ms` `(int, default: 300000)`
  Controls how long an idle UDP flow line is kept alive before the tunnel closes it.
- `fake-dns` `(bool or object, default: false)`
  Enables an in-tunnel fake DNS responder for IPv4 A queries. Mapped fake-IP destinations are converted back into domain destinations on generated TCP/UDP Waterwall lines.

The minimum allowed `udp-idle-timeout-ms` value is `1`.

`fake-dns` object fields:

- `enabled` `(bool, default: true)`
- `address` `(IPv4 string, default: "198.18.0.2")`
- `port` `(int, default: 53)`
- `network` `(IPv4 string, default: "100.64.0.0")`
- `netmask` `(IPv4 string, default: "255.192.0.0")`
- `cache-size` `(int, default: 10000)`
- `ttl` `(int seconds, default: 1)`

The legacy key `mapdns` is accepted as an alias for `fake-dns`. The key `fake_dns` is also accepted.

### Example

```json
{
  "name": "ptc",
  "type": "PacketsToConnection",
  "settings": {
    "udp-idle-timeout-ms": 120000,
    "fake-dns": {
      "address": "198.18.0.2",
      "network": "100.64.0.0",
      "netmask": "255.192.0.0",
      "cache-size": 10000
    }
  },
  "next": "service-chain-entry"
}
```

## Typical Placement

Example packet-to-service chain:

```text
TunDevice <--> PacketsToConnection <--> TcpConnector
```

or:

```text
WireGuardDevice <--> PacketsToConnection <--> HttpClient
```

The key idea is that the previous side is packet-oriented, while the next side is normal Waterwall connection-oriented chaining.

## Limitations

- IPv6 is not implemented
- ICMP is not implemented
- UDP pause is lossy, not queued
- IPv4 route/netif contexts are created on demand per packet worker, not per destination IP, and are not currently exposed as a tuning surface
- TCP and UDP listeners are pretend wildcard PCBs on the worker-local netif, not one listener per destination port
- this node assumes packet payload really is IP traffic and does not validate every malformed edge case beyond conservative basic checks
- this node is not a packet-framing tunnel and does not add per-payload headers; its node declares no extra left-padding requirement

## Difference From PacketsToStream

Use `PacketsToStream` when you only need to preserve packet boundaries over a stream transport.

Use `PacketsToConnection` when you need lwIP to reconstruct transport flows and expose them as normal Waterwall lines.
