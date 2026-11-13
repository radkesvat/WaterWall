# EnetClient

`EnetClient` carries each application stream over a UDP path as one native ENet
connection. `EnetServer` accepts those connections and gives each one its own
stream toward the destination. The wire format is unmodified ENet 1.3.18:
reliable, ordered packets on one channel.

```text
Client: TcpListener -> EnetClient -> UdpConnector
                                  == one ENet connection per stream, over UDP ==>
Server: UdpListener -> EnetServer -> TcpConnector
```

Both nodes operate on layer-4 lines. `EnetClient` accepts a reliable byte stream
from the previous node and sends ENet datagrams to the next node. Payload
boundaries are not preserved: what arrives on the other side is the same bytes
in the same order.

## Transport placement

- Before `EnetClient`: any node that produces a byte stream, such as
  `TcpListener` or a proxy protocol node.
- After `EnetClient`: a path that keeps datagram boundaries. In practice that is
  `UdpConnector`, directly or behind tunnels that pass datagrams unchanged.
- Every stream that enters gets its own carrier line toward `next` and its own
  ENet connection. Streams do not share a connection.
- The remote side is `EnetServer`, or any ENet 1.3 application that uses the
  library defaults (no checksum, no compression) and exchanges reliable packets
  on channel 0.

## Configuration

```json
{
  "name": "enet-client",
  "type": "EnetClient",
  "next": "udp-out",
  "settings": {
    "send-mtu": 1400
  }
}
```

### Top-level fields

| Field | Requirement |
| --- | --- |
| `name` | Required node name, unique within the configuration. |
| `type` | Exactly `"EnetClient"`. |
| `next` | Required name of the node that carries the datagrams. |
| `settings` | Optional object. Every setting has a default. |

### Settings

Settings are integers. A value of another type, a fraction, null, or a number
outside the range rejects startup with a message that names the setting.

| Setting | Default | Meaning |
| --- | --- | --- |
| `send-mtu` | core `misc.mtu` | IPv4 packet budget for outgoing datagrams, from `604` to `65535`. See [Sending MTU](#sending-mtu). |
| `no-recv-timeout-ms` | `30000` | Liveness timeout `T`, from `1` to `2147483647`. A connection whose packets stay unacknowledged ends between `T` and about `2T`. |
| `ping-interval-ms` | `10000` | Silence after which ENet sends a ping, from `1`. It must be smaller than `no-recv-timeout-ms`. |
| `send-buffer-limit` | `524288` | Accepted but unacknowledged bytes above which the previous node is paused, from `4096` to `134217728`. |
| `receive-buffer-limit` | `1048576` | Limit for received data that waits behind a missing packet, from `131072` to `268435456`. The largest accepted ENet packet is half of it. |
| `carrier-queue-limit` | `256` | Datagrams that one ENet call may hand to the next node, from `1` to `65535`. |
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

`send-mtu` is an IPv4 packet budget, with the same meaning as in `KcpClient`.
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
fixed IPv4 allowance, and tunnels after this node add their own bytes. Lower
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
  four times as much, and one stream that `ConnectionStripeClient` spread over
  eight ENet connections carried 76 to 83 Mbit/s on the same path.
- **A dead peer is found through missing acknowledgements.** An idle connection
  sends a ping after `ping-interval-ms`. A peer that stops answering is detected
  between `T` and about `2T` after the first unanswered packet, where `T` is
  `no-recv-timeout-ms`. With the defaults, a frozen peer was detected 33 to 35
  seconds after that packet.
- **A connection is bound to its carrier.** If the client's UDP source address
  changes, the server sees a new carrier, and the old connection times out.
- **No encryption and no authentication.** ENet sends every byte in clear text
  and accepts any peer. Use security nodes on the stream side, before
  `EnetClient` and after `EnetServer`, when those properties are needed.

## Flow control and memory

- The previous node is paused while more than `send-buffer-limit` bytes are
  accepted but not yet acknowledged by the peer, and resumed at or below half of
  that. A pause from the next node also pauses the previous node; either reason
  alone keeps it paused.
- A payload offered while more than twice `send-buffer-limit` bytes are
  outstanding is refused, and that connection is closed. A previous node that
  honors Pause does not reach this.
- When the previous node pauses the downstream direction, `EnetClient` pauses
  the next node, which stops datagram intake. That also stops acknowledgements:
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

- When the previous node finishes the stream, `EnetClient` accepts no more
  bytes, lets ENet deliver every byte it already accepted, and then disconnects
  natively. The connection keeps its own carrier line for this after the
  application line is gone. Bytes that arrive from the peer after that Finish
  are discarded: a Finish closes both directions of the stream.
- `close-drain-timeout-ms` after that Finish the node stops waiting, sends one
  disconnect and closes. It logs a warning with the number of unacknowledged
  bytes. A close that finished earlier is not proof of delivery either: ENet
  reports the end of a close in the same way when the peer times out.
- When the peer disconnects, bytes that arrived before the disconnect are
  delivered first and the previous node then receives Finish. Bytes that were
  still unsent locally are discarded; ENet has no half-close.
- When the next node finishes the carrier, the connection ends at once and the
  previous node receives Finish.
- A connect request that gets no answer ends by the same liveness timeout.
- At shutdown every connection ends without waiting for a drain.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| The stream opens, but no data arrives and it closes after 30 to 60 seconds | The carrier being ready only means that the UDP socket exists. Check that the datagrams reach an `EnetServer` and that the answers come back, and that no hop drops datagrams of `send-mtu` size. |
| One transfer is slow on a long path, while the link has capacity | This is ENet's window of 64 KiB per round trip. Parallel streams each get their own window, and `ConnectionStripeClient` before this node gives one stream several connections. |
| Startup fails and names `send-mtu`, although the node does not set it | Core `misc.mtu` is below `604`. Set `send-mtu` in the node. |
| Log line `the send limit refused a payload` | The previous node kept sending after Pause. Check the nodes before `EnetClient`, or raise `send-buffer-limit`. |
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

Runnable configurations are in [examples/udp](examples/udp) for the plain pair
and in [examples/stripe](examples/stripe) for one stream over several ENet
connections.
