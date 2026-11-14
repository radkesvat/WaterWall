# GnsClient

`GnsClient` carries each application stream over a UDP path as one native
GameNetworkingSockets connection. `GnsServer` accepts those connections and
gives each one its own stream toward the destination. The wire format is the
unmodified UDP protocol of Valve's open-source GameNetworkingSockets library:
reliable messages on one connection.

```text
Client: TcpListener -> GnsClient -> UdpConnector
                                 == one GNS connection per stream, over UDP ==>
Server: UdpListener -> GnsServer -> TcpConnector
```

Both nodes operate on layer-4 lines. `GnsClient` accepts a reliable byte stream
from the previous node and sends GNS datagrams to the next node. Payload
boundaries are not preserved: what arrives on the other side is the same bytes
in the same order.

GameNetworkingSockets sends at a configured rate and has no congestion control.
Set `send-rate` for the path; the default is about 2 Mbit/s.

## Transport placement

- Before `GnsClient`: any node that produces a byte stream, such as
  `TcpListener` or a proxy protocol node.
- After `GnsClient`: a path that keeps datagram boundaries. In practice that is
  `UdpConnector`, directly or behind tunnels that pass datagrams unchanged.
- Every stream that enters gets its own carrier line toward `next` and its own
  GNS connection. Streams do not share a connection.
- The remote side is `GnsServer`, or any GameNetworkingSockets application that
  listens with `CreateListenSocketIP`, uses the library's defaults and exchanges
  reliable messages.

## Configuration

```json
{
  "name": "gns-client",
  "type": "GnsClient",
  "next": "udp-out",
  "settings": {
    "send-mtu": 1400,
    "send-rate": 4194304
  }
}
```

### Top-level fields

| Field | Requirement |
| --- | --- |
| `name` | Required node name, unique within the configuration. |
| `type` | Exactly `"GnsClient"`. |
| `next` | Required name of the node that carries the datagrams. |
| `settings` | Optional object. Every setting has a default. |

### Settings

Settings are integers. A value of another type, a fraction, null, or a number
outside the range rejects startup with a message that names the setting.

| Setting | Default | Meaning |
| --- | --- | --- |
| `send-mtu` | core `misc.mtu` | IPv4 packet budget for outgoing datagrams, from `228` to `65535`. See [Sending MTU](#sending-mtu). |
| `send-rate` | `262144` | Bytes per second that one connection sends, from `1024` to `104857600`. See [Send rate](#send-rate). |
| `no-recv-timeout-ms` | `30000` | Liveness timeout `T`, from `1` to `2147483647`. A connection ends when nothing arrives from the peer for `T`, and when the peer acknowledges nothing of what waits for `T`. |
| `timeout-initial-ms` | `10000` | How long the connection attempt may take, from `1` to `2147483647`. |
| `send-buffer-limit` | `524288` | Accepted but unacknowledged bytes above which the previous node is paused, from `4096` to `134217728`. A value above half of GNS's packet window, which is 9,600,000 bytes with a `send-mtu` of 1328 or more, is lowered to that with a warning. |
| `receive-buffer-limit` | `1048576` | Limit for received data that waits behind a missing packet, from `131072` to `268435456`. The largest accepted GNS message is half of it. |
| `carrier-queue-limit` | `256` | Datagrams that may wait for the next node, from `1` to `65535`. |
| `close-drain-timeout-ms` | `30000` | How long a closing connection may wait for the peer to acknowledge the remaining bytes, from `1` to `2147483647`. |

Each side applies its own values; nothing is negotiated. `send-rate` is the
rate of this side's own sending, so the two directions of a connection can have
different rates.

## Sending MTU

`send-mtu` is an IPv4 packet budget, with the same meaning as in `KcpClient`.
GNS's datagram limit is:

```text
GNS packet size = min(send-mtu - 28, 1300)
```

The 28 bytes are the IPv4 and UDP headers, and 1300 is GNS's protocol maximum.
With the core default of `1500` the limit is 1300 bytes. A budget above `1328` is
valid and uses 1300. A budget below `228` rejects startup, whether it is written
in the node or inherited from core `misc.mtu`, because GNS's smallest packet
size is 200 bytes.

Each side limits only what it sends. Receiving does not depend on the local
budget: a datagram of up to 1300 bytes is accepted. The first packet of every
connection attempt is 512 bytes, whatever the budget.

This is not path-MTU discovery. An IPv6 header needs 20 more bytes than the
fixed IPv4 allowance, and tunnels after this node add their own bytes. Lower
`send-mtu` to leave room for them.

## Send rate

GNS sends at `send-rate` whenever it has data, and it does not slow down when
packets are lost. The rate is per connection and per direction.

- **Below the path's capacity the connection carries the rate.** Between two
  hosts with a round trip of 44 ms, one connection carried 2.0 Mbit/s at the
  default rate, 8.0 Mbit/s at `1048576`, 30.8 Mbit/s at `4194304` and, with
  larger buffers, 129.5 Mbit/s at `16777216`. That is 92 to 97% of the
  configured rate; packet headers take the rest. At `33554432` the same
  connection carried 209 to 228 Mbit/s, about 80% of the rate.
- **Raise the buffer limits with the rate.** The previous node is paused at
  `send-buffer-limit`, so that limit has to hold what is in flight during a
  round trip. On the same path, `8388608` carried 41 Mbit/s with the default
  limits, 62 Mbit/s with a `send-buffer-limit` of 1 MiB and 65 Mbit/s with 2 MiB;
  `16777216` carried 47, 123 and 130 Mbit/s with the default, 2 MiB and 4 MiB.
  A quarter of a second of `send-rate` was enough there. Set
  `receive-buffer-limit` on the other side to twice that.
- **GNS does not slow down for a full path.** What does not fit is dropped on
  the way and sent again at the same rate. Through a bottleneck of 20 Mbit/s, a
  connection set to 16.8 Mbit/s carried 16.2 Mbit/s, and connections set to
  33.6 and 67.1 Mbit/s carried 14.8 and 17.3 Mbit/s while the bottleneck dropped
  the excess. A rate above the capacity gains nothing and takes the path from
  other traffic. Set the rate at or below what the path carries.
- **Loss costs more than on a protocol that adapts.** After a lost packet GNS
  can hold only `receive-buffer-limit` bytes beyond the gap, and the sender
  repeats what did not fit. On a simulated link with a round trip of 100 ms and
  1% loss, a rate of 10 MB/s carried 3.7 to 4.7 MB/s with the default
  `receive-buffer-limit` and 8.8 MB/s with 16 MiB.
- **The rate is per connection.** Four parallel streams at `4194304` carried
  123 Mbit/s together, and one stream that `ConnectionStripeClient` spread over
  eight connections at `2097152` each carried 129 Mbit/s.

For comparison, on the same path one `EnetClient` connection carried 13 Mbit/s
and one `KcpClient` connection 51 to 67 Mbit/s.

## Other native limits

These limits come from the GameNetworkingSockets library. They cannot be
removed without giving up native compatibility.

- **The first packet is mostly zeros.** A connection attempt starts with a
  512-byte datagram that holds about twenty bytes of content and zeros after
  them. Some networks drop such datagrams; on the path of the measurements
  above they never arrived, and no connection opened. A node that changes the bytes on the wire
  gets through: with `ObfuscatorClient` after `GnsClient` and `ObfuscatorServer`
  before `GnsServer` the same path carried every number given here. See
  [examples/obfuscated](examples/obfuscated).
- **Data is encrypted, peers are not authenticated.** GNS encrypts every data
  packet with AES-256-GCM, with keys from a Curve25519 exchange. The open-source
  library has no certificate authority, so this hides the content from an
  observer but does not prove who the peer is. Use security nodes on the stream
  side, before `GnsClient` and after `GnsServer`, when that is needed.
- **One lock for the whole process.** GNS processes every datagram of every
  connection under one lock and keeps one service thread. All GNS connections of
  a process share that capacity, on any number of workers. One connection that
  received 265 Mbit/s used a little more than one core.
- **A process holds about 65,000 GNS connections,** counting those that closed
  within the last five seconds.
- **At most 16,000 packets may wait for acknowledgement.** GNS numbers packets
  with 16 bits. The node therefore never lets more than 16,000 packets' worth of
  bytes, and never more than 8,192 messages, wait on one connection, whatever
  `send-buffer-limit` says, and it ends a connection whose round trip holds more
  packets than that at the current rate.
- **The close notice is sent once.** A peer that misses it, and sends nothing
  itself, sees the end of the connection only by its liveness timeout.
- **A dead peer is found through missing answers.** The connection ends
  `no-recv-timeout-ms` after the first packet that got no answer, and an idle
  connection sends such a packet every ten seconds. With the defaults the frozen
  peer of an idle connection was detected 39 seconds after it stopped.
- **A connection is bound to its carrier.** If the client's UDP source address
  changes, the server sees a new carrier, and the old connection times out.

## Flow control and memory

- The previous node is paused while more than `send-buffer-limit` bytes are
  accepted but not yet acknowledged by the peer, and resumed at or below half of
  that. A pause from the next node also pauses the previous node; either reason
  alone keeps it paused. GNS counts one to three framing bytes with every
  message, so the pause comes slightly before the limit.
- A payload offered while more than twice `send-buffer-limit` bytes are
  outstanding is refused, and that connection is closed. A previous node that
  honors Pause does not reach this.
- When the previous node pauses the downstream direction, `GnsClient` pauses
  the next node, which stops datagram intake. That also stops acknowledgements:
  a pause longer than the liveness timeout can end the connection.
- At `receive-buffer-limit` GNS refuses data that arrives ahead of a missing
  packet, and the peer sends it again. Acknowledged bytes are never discarded,
  and one connection holds less than twice the limit. A received GNS message
  larger than half of the limit ends the connection.
- More than `carrier-queue-limit` datagrams waiting for the next node are
  refused. GNS keeps their data and offers it again a moment later. The
  connection stays open.

## Close and timeouts

- When the previous node finishes the stream, `GnsClient` accepts no more
  bytes, lets GNS deliver every byte it already accepted, and then closes the
  connection natively. The connection keeps its own carrier line for this after
  the application line is gone, and for one more second after the close, so
  that the notice and the answers to late packets can pass. Bytes that arrive
  from the peer after that Finish are discarded: a Finish closes both directions
  of the stream.
- `close-drain-timeout-ms` after that Finish the node stops waiting, sends the
  close notice and closes. It logs a warning with the number of unacknowledged
  bytes.
- When the peer closes, bytes that arrived before the close are delivered first
  and the previous node then receives Finish. Bytes that were still unsent
  locally are discarded; GNS has no half-close.
- When the next node finishes the carrier, the connection ends at once and the
  previous node receives Finish.
- A connection attempt that gets no answer ends after `timeout-initial-ms`. GNS
  repeats its first packet every half second until then.
- At shutdown every connection ends without waiting for a drain.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| The stream opens, but no data arrives and it closes after 10 seconds | The carrier being ready only means that the UDP socket exists. The connection attempt got no answer within `timeout-initial-ms`. Check that the datagrams reach a `GnsServer` and that the answers come back. If small datagrams arrive and the first GNS packet does not, the path drops datagrams that are mostly zeros: put `ObfuscatorClient` and `ObfuscatorServer` around the UDP path. |
| Transfers are slow, while the link has capacity | `send-rate` is the limit. The default is 262144 bytes per second. Raise it on the side that sends, and raise `send-buffer-limit` there and `receive-buffer-limit` on the other side with it. |
| Raising `send-rate` does not make transfers faster | Either `send-buffer-limit` holds the sender back, or the rate is above what the path carries and GNS repeats the dropped packets. Raise the limits with the rate, and keep the rate at or below the path's capacity. |
| Startup fails and names `send-mtu`, although the node does not set it | Core `misc.mtu` is below `228`. Set `send-mtu` in the node. |
| Log line `the send limit refused a payload` | The previous node kept sending after Pause. Check the nodes before `GnsClient`, or raise `send-buffer-limit`. |
| Log line `close delivery unconfirmed at the fixed deadline` | The peer did not acknowledge the last bytes within `close-drain-timeout-ms`. Check loss on the path, or raise the timeout for slow paths. |
| Debug log line `the peer acknowledged nothing for no-recv-timeout-ms` | The peer's packets arrive, but it confirms none of this side's. Check the direction from this node to the peer. |

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

Runnable configurations are in [examples/udp](examples/udp) for the plain pair,
in [examples/obfuscated](examples/obfuscated) for a path that drops GNS's first
packet, and in [examples/stripe](examples/stripe) for one stream over several
GNS connections.
