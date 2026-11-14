# EnetServer

`EnetServer` accepts native ENet connections that arrive over a UDP path and
gives each one its own stream toward the next node. It is the remote side of
`EnetClient`. The wire format is unmodified ENet 1.3.18: reliable, ordered
packets on one channel.

```text
Client: TcpListener -> EnetClient -> UdpConnector
                                  == one ENet connection per stream, over UDP ==>
Server: UdpListener -> EnetServer -> TcpConnector
```

Both nodes operate on layer-4 lines. `EnetServer` receives ENet datagrams from
the previous node and sends a reliable byte stream to the next node. Payload
boundaries are not preserved: the next node receives the same bytes in the same
order.

## Transport placement

- Before `EnetServer`: a path that keeps datagram boundaries and gives every
  remote peer its own line. In practice that is `UdpListener`, directly or
  behind tunnels that pass datagrams unchanged.
- After `EnetServer`: any node that consumes a byte stream, such as
  `TcpConnector` or a proxy protocol node.
- Every carrier line holds at most one ENet connection. The stream line toward
  `next` is created when ENet has accepted the connection, not when the first
  datagram arrives. It carries the carrier's source and destination addresses
  and is marked as a stream.
- The remote side is `EnetClient`, or any ENet 1.3 application that uses the
  library defaults (no checksum, no compression) and exchanges reliable packets
  on channel 0.

## Configuration

```json
{
  "name": "enet-server",
  "type": "EnetServer",
  "next": "destination",
  "settings": {
    "send-mtu": 1400
  }
}
```

### Top-level fields

| Field | Requirement |
| --- | --- |
| `name` | Required node name, unique within the configuration. |
| `type` | Exactly `"EnetServer"`. |
| `next` | Required name of the node that receives the streams. |
| `settings` | Optional object. Every setting has a default. |

### Settings

Settings are integers. A value of another type, a fraction, null, or a number
outside the range rejects startup with a message that names the setting.

| Setting | Default | Meaning |
| --- | --- | --- |
| `send-mtu` | core `misc.mtu` | IPv4 packet budget for outgoing datagrams, from `604` to `65535`. See [Sending MTU](#sending-mtu). |
| `no-recv-timeout-ms` | `30000` | Liveness timeout `T`, from `1` to `2147483647`. A connection whose packets stay unacknowledged ends between `T` and about `2T`. A carrier without an accepted connection is finished after `T`. |
| `ping-interval-ms` | `10000` | Silence after which ENet sends a ping, from `1`. It must be smaller than `no-recv-timeout-ms`. |
| `send-buffer-limit` | `524288` | Accepted but unacknowledged bytes above which the next node is paused, from `4096` to `134217728`. |
| `receive-buffer-limit` | `1048576` | Limit for received data that waits behind a missing packet, from `131072` to `268435456`. The largest accepted ENet packet is half of it. |
| `carrier-queue-limit` | `256` | Datagrams that one ENet call may hand to the previous node, from `1` to `65535`. |
| `close-drain-timeout-ms` | `30000` | How long a closing connection may wait for the peer to acknowledge the remaining bytes, from `1` to `2147483647`. |
| `incoming-bandwidth` | `0` | ENet's incoming bandwidth in bytes per second, from `0` to `4294967295`. `0` means unlimited. |
| `outgoing-bandwidth` | `0` | ENet's outgoing bandwidth in bytes per second, from `0` to `4294967295`. `0` means unlimited. |

Each side applies its own values; nothing but the datagram size and the reliable
window is negotiated. A `no-recv-timeout-ms` of `10000` or less also needs a
smaller `ping-interval-ms`.

The bandwidth settings are passed to ENet unchanged. ENet uses them to size its
reliable window and its packet throttle; they are not an exact rate limit. A
nonzero value below `1048576` lowers the window: 4,096 bytes for each 65,536
bytes per second, and never less than 4,096 bytes.

## Sending MTU

`send-mtu` is an IPv4 packet budget, with the same meaning as in `KcpServer`.
ENet's datagram limit is:

```text
ENet MTU = min(send-mtu - 28, 4096)
```

The 28 bytes are the IPv4 and UDP headers, and 4096 is ENet's protocol maximum.
With the core default of `1500` the limit is 1472 bytes. A budget above `4124` is
valid and uses 4096. A budget below `604` rejects startup, whether it is written
in the node or inherited from core `misc.mtu`, because ENet's smallest MTU is
576 bytes.

ENet negotiates the smaller of the two peers' limits during connect, so each
side's budget bounds both directions. Receiving does not depend on the local
budget: a datagram of up to 4096 bytes is accepted.

This is not path-MTU discovery. An IPv6 header needs 20 more bytes than the
fixed IPv4 allowance, and tunnels before this node add their own bytes. Lower
`send-mtu` to leave room for them.

## Throughput and other native limits

These limits come from the ENet protocol. They cannot be removed without giving
up native compatibility.

- **One connection carries about 64 KiB per round trip.** ENet keeps at most
  65,536 bytes of reliable data in flight on a connection, and both peers clamp
  that window. One stream therefore carries at most `65536 * 8 / RTT` bits per
  second: about 26 Mbit/s at 20 ms, 10.5 Mbit/s at 50 ms, 5.2 Mbit/s at 100 ms
  and 2.6 Mbit/s at 200 ms. On a simulated link the node reaches that bound
  without loss, 97% of it at 100 ms with 1% loss, and 76% at 100 ms with 5% loss.
  Between two hosts with round trips of 38 to 45 ms, single streams carried 11.6
  to 13.6 Mbit/s. The limit is per connection: four parallel streams carried
  four times as much, and one stream that `ConnectionStripeServer` joined from
  eight ENet connections carried 76 to 83 Mbit/s on the same path.
- **A dead peer is found through missing acknowledgements.** An idle connection
  sends a ping after `ping-interval-ms`. A peer that stops answering is detected
  between `T` and about `2T` after the first unanswered packet, where `T` is
  `no-recv-timeout-ms`. With the defaults, a frozen peer was detected 33 to 35
  seconds after that packet.
- **A connection is bound to its carrier.** If the client's UDP source address
  changes, the previous node opens a new carrier, and the old connection times
  out.
- **No encryption and no authentication.** ENet sends every byte in clear text
  and accepts any peer, without an address-validation exchange. Before a
  connection is accepted, each carrier costs one small ENet host for at most
  `no-recv-timeout-ms`. Use security nodes on the stream side, before
  `EnetClient` and after `EnetServer`, when those properties are needed.

## Flow control and memory

- The next node is paused while more than `send-buffer-limit` bytes are accepted
  but not yet acknowledged by the peer, and resumed at or below half of that. A
  pause from the previous node also pauses the next node; either reason alone
  keeps it paused.
- A payload offered while more than twice `send-buffer-limit` bytes are
  outstanding is refused, and that connection is closed. A next node that honors
  Pause does not reach this.
- When the next node pauses the upstream direction, `EnetServer` pauses the
  previous node, which stops datagram intake. That also stops acknowledgements:
  a pause longer than the liveness timeout can end the connection.
- At `receive-buffer-limit` ENet stops acknowledging data that arrives ahead of
  a missing packet, and the peer sends it again later. The missing packet itself
  is still accepted, so a loss cannot lock the stream. Acknowledged bytes are
  never discarded, and one connection holds less than two and a half times the
  limit. A received ENet packet larger than half of the limit is never
  acknowledged, so that connection ends by the peer's timeout.
- Datagrams above `carrier-queue-limit` in one ENet call are dropped and ENet
  sends them again after its timeout. The connection stays open.

## Close and timeouts

- When the next node finishes the stream, `EnetServer` accepts no more bytes,
  lets ENet deliver every byte it already accepted, and then disconnects
  natively. The previous node receives Finish on the carrier only after that.
  Bytes that arrive from the peer after the next node's Finish are discarded: a
  Finish closes both directions of the stream.
- `close-drain-timeout-ms` after that Finish the node stops waiting, sends one
  disconnect and closes. It logs a warning with the number of unacknowledged
  bytes. A close that finished earlier is not proof of delivery either: ENet
  reports the end of a close in the same way when the peer times out.
- When the peer disconnects, bytes that arrived before the disconnect are
  delivered first. The next node then receives Finish, and the previous node
  receives Finish on the carrier. Bytes that were still unsent locally are
  discarded; ENet has no half-close.
- When the previous node finishes the carrier, the connection ends at once and
  the next node receives Finish.
- A carrier on which no ENet connection is accepted within `no-recv-timeout-ms`
  is finished. No stream line is created for it.
- At shutdown every connection ends without waiting for a drain.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| Datagrams arrive, but the next node never sees a stream | The stream is created only after ENet's connect exchange. Check that the answers reach the client, that the peer speaks ENet with the library defaults, and that no hop drops datagrams of `send-mtu` size. |
| One transfer is slow on a long path, while the link has capacity | This is ENet's window of 64 KiB per round trip. Parallel streams each get their own window, and `ConnectionStripeServer` after this node joins several connections into one stream. |
| Startup fails and names `send-mtu`, although the node does not set it | Core `misc.mtu` is below `604`. Set `send-mtu` in the node. |
| Log line `the send limit refused a payload` | The next node kept sending after Pause. Check the nodes after `EnetServer`, or raise `send-buffer-limit`. |
| Log line `close delivery unconfirmed at the fixed deadline` | The peer did not acknowledge the last bytes within `close-drain-timeout-ms`. Check loss on the path, or raise the timeout for slow paths. |

## Node Metadata

Source-backed values from `instance/node.c`:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagBlocksSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `0` bytes |

Splice is disabled for chains that contain this node. Every datagram is built
in a new buffer, so no left padding is reserved.

Runnable configurations are in
[../EnetClient/examples/udp](../EnetClient/examples/udp) for the plain pair and
in [../EnetClient/examples/stripe](../EnetClient/examples/stripe) for one stream
over several ENet connections.
