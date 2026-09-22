<!--
Documentation version: 153
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/UdpStatelessSocket.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/UdpStatelessSocket.mdx, and all files must keep the same documentation version.
-->

# UdpStatelessSocket Node

`UdpStatelessSocket` is a UDP chain-head adapter. It binds one UDP socket, receives datagrams from any peer, and creates normal WaterWall lines for inbound peer flows.

It exists primarily to support components such as `WireGuardDevice`, which need one UDP socket that can both send to configured peers and accept packets from peers that contact the socket first.

## What It Does

- Binds a UDP socket on a configured local address and port.
- Receives UDP datagrams from any remote peer.
- Keys inbound peer flows by peer endpoint, local endpoint, and tunnel identity.
- Creates one normal line per inbound peer flow and forwards received datagrams over that line.
- Sends outbound datagrams on owned peer lines back to the stored peer endpoint.
- Sends outbound datagrams on other lines to the destination address stored in the line's routing context.
- Receives peer traffic upstream toward `next` and accepts outgoing datagrams downstream from `next`.

Inbound peer lines use `UdpListener`-style idle lifetimes: a short init timeout and a longer keepalive timeout after traffic starts.

## Typical Placement

The supported layout starts with `UdpStatelessSocket`:

```text
UdpStatelessSocket -> WireGuardDevice -> packet side node
```

Head-only placement is the current design decision, not a temporary restriction. A previous node or a missing next node is rejected at startup. Tail placement and downstream peer initialization are disabled.

`UdpStatelessSocket` is meant to sit at the UDP edge of a chain when a component needs one socket for UDP send/receive while still giving received peers distinct WaterWall line lifetimes.

## Configuration Example

```json
{
  "name": "wg-udp-socket",
  "type": "UdpStatelessSocket",
  "settings": {
    "listen-address": "0.0.0.0",
    "listen-port": 51820,
    "interface": "eth0",
    "fwmark": 10,
    "large-send-buffer": true,
    "large-recv-buffer": true,
    "source-ip": "192.0.2.10",
    "verbose": false
  },
  "next": "wg"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"UdpStatelessSocket"`.

### `settings`

- `listen-address` `(string)`
  Local IP address to bind.

  This must be a valid IP address string.

- `listen-port` `(integer)`
  Local UDP port to bind.

  Valid range: `0` to `65535`

## Optional `settings` Fields

- `interface` `(string)`
  Restricts the UDP socket to a local network device where supported.
  On Linux this uses `SO_BINDTODEVICE`. On platforms without device binding, WaterWall falls back to binding the socket to the interface's IPv4 address when `source-ip` is not set.

- `fwmark` `(integer)`
  Linux-style socket mark.
  When the platform provides `SO_MARK`, this value is applied to the UDP socket before bind.
  Default: not set

- `source-ip` `(string)`
  Uses a specific local source IP for the UDP socket.
  For this stateless socket, `source-ip` is treated as an override for `listen-address`, because the same bound UDP socket is used for both receiving and sending.
  If `TunDevice` loop protection has published an automatic egress pin, `source-ip` alone does not override that pin. Make sure the source IP belongs to the pinned/default interface, or set `interface` explicitly.

- `large-send-buffer` `(boolean or positive integer)`
  Sets `SO_SNDBUF` on the UDP socket.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged. A positive integer sets the requested byte size directly.
  Default: `true`

- `large-recv-buffer` `(boolean or positive integer)`
  Sets `SO_RCVBUF` on the UDP socket.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged. A positive integer sets the requested byte size directly.
  Default: `true`

- `verbose` `(boolean)`
  Enables per-packet debug logs for UDP datagrams received from and sent to peers.
  Default: `false`

## Detailed Behavior

### Peer receive path

When a UDP datagram arrives on the bound socket:

- `UdpStatelessSocket` builds a flow key from the UDP peer endpoint, the local socket endpoint, and this tunnel instance
- if no matching flow exists, it creates a normal line, initializes this tunnel's line state, and sends upstream `Init` toward `next`
- it writes the peer endpoint into the line source routing context and records the local listener port
- it forwards the datagram body over that peer's line

Received datagrams always enter from the head and are forwarded upstream toward `next`.

### Send path

When payload is sent through `UdpStatelessSocket`:

- if the line was created for an inbound peer, the datagram is sent back to that stored peer endpoint
- otherwise, the tunnel reads the destination address from `l->routing_context.dest_ctx`
- unresolved routing-context domains are resolved asynchronously
- async results are cached by domain, port, and strategy for 30 minutes in a fixed 256-entry FIFO. Existing keys
  refresh in place, expired entries are reclaimed before insertion, and the oldest entry is evicted when the cap is full
- the destination IP and port are converted to a socket address and sent through the bound socket

This keeps compatibility with packet-line producers such as `WireGuardDevice` while allowing inbound peers to keep distinct return paths.

### Listener and connector role

Although the implementation always binds a local UDP socket, the tunnel can act like either side of a peer exchange:

- it can receive packets from arbitrary peers like a listener
- it can also send packets to a chosen peer like a connector

That combination is why it is useful for `WireGuardDevice`, where the device may need to initiate contact to a peer or receive the first packet from a peer using the same stateless UDP socket.

### Chain integration

`UdpStatelessSocket` always owns new peer lines at the head. It sends upstream `Init`, payload, and local/idle-expiry `Finish` toward `next`. Downstream `Finish` from `next` closes an owned peer line without reflecting a callback. Downstream sends on borrowed transport or packet lines remain supported. Calls into the adapter from a previous/upstream node are disabled.

### Worker behavior

The UDP socket is created on one worker loop.

If payload to be sent originates from a different worker:

- the send is scheduled onto the socket-owning worker
- the actual UDP write is then performed there

This preserves correct ownership of the socket while still allowing payload to come from any worker line.

### Connection semantics

`UdpStatelessSocket` owns only the peer lines it creates from inbound UDP datagrams. Those lines are closed when the adjacent chain side sends `Finish` or when the idle timer expires.

Packet lines are still supported for outbound routing-context sends, but received datagrams are no longer forwarded over the worker packet line.

## Notes And Caveats

- `UdpStatelessSocket` is intended for UDP edge traffic, especially around `WireGuardDevice`.
- For non-owned lines, the tunnel depends on valid routing context for outbound sends. In particular, `dest_ctx` must be initialized before sending payload.
- For packet lines, unresolved domain sends snapshot the domain and port for that datagram before resolving, because packet-line routing context is scratch metadata.
- Received UDP peers get distinct normal lines; packet lines are not destroyed during runtime.
- `fwmark` and device binding are platform-dependent. `fwmark` is not available on Windows.
- The JSON parser requires `listen-address` and `listen-port`; `source-ip` may override the effective local bind address.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainHead` &#124; `kNodeFlagSupportsSplice` |
| `can_have_prev` | `false` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayerAnything` |
| `layer_group_prev_node` | `kNodeLayerNone` |
| `layer_group_next_node` | `kNodeLayerAnything` |
| `required_padding_left` | `0` bytes |

## UDP splice sending

UDP receives remain ordinary buffers. On an eligible Linux chain, UDP sends accept ordinary data or a real prefix plus a private-pipe body as one datagram to its explicit destination, including empty datagrams. Supported layouts use pipe-to-socket splice. Highly fragmented pipes, or failure to establish a safe fragment bound before sending, use a complete ordinary fallback before socket assembly. Oversized datagrams are rejected without splitting.

Pressure before assembly retains the existing drop policy, without a UDP retry queue. An incomplete splice or failed commit after priming retires only the affected socket; its associated normal lines close through their owners. Shared-socket peers can therefore close together. No truncated remainder is retried, and unrelated sockets remain active. Ordinary sends retain their existing error policy.

The flag does not bypass platform support, `misc.splice`, packet exclusion, or support from every node in the final expanded/merged chain. No end-to-end zero-copy or measured performance gain is promised.

The socket remains chain-head-only. Its I/O worker serializes local and posted sends. Local buffers return to the local pool; detached cross-worker and canceled buffers are physically destroyed. Ordinary sends retain the existing EINTR retry behavior; incomplete splice assembly is never retried.
