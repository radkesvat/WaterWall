# ConnectionStripeServer

`ConnectionStripeServer` joins the transport connections opened by
`ConnectionStripeClient` into one ordered, full-duplex application stream. For an
eight-member group, it accepts eight transports and creates exactly one line
through its `next` path. Every member may carry both upload and download.

```text
TcpListener -> TlsServer -> ConnectionStripeServer -> TcpConnector
```

All members of a group must reach this same node instance in one WaterWall
process. The transport path must provide reliable, ordered bytes on each member.
The combined application stream remains ordered even when different members
deliver their records in a different order.

For TLS, place `TlsServer` before this node so it receives decrypted Stripe
frames. For KCP, use `UdpListener -> KcpServer -> ConnectionStripeServer` so
KCP supplies the reliable stream. Direct UDP and application message boundaries
are not supported by the Stripe framing. See
[ConnectionStripeClient](../ConnectionStripeClient/description.md#transport-placement)
for matching transport paths.

Groups are local to this node instance. Separate server processes or replicas
do not share the session table; an external load balancer must keep every member
of a group on the same instance. This node has no `pair` setting.

## Sharing a striped group with Mux

For a fixed service, pair these chains:

```text
Server 1: TcpListener -> MuxClient -> ConnectionStripeClient -> TcpConnector
Server 2: TcpListener -> ConnectionStripeServer -> MuxServer -> TcpConnector(service)
```

The Stripe server reconstructs one Mux parent stream per group. MuxServer then
opens one service connection per decoded child; a group can therefore serve many
application connections. `max-connections` limits carriers per group, not Mux
children or service connections. Mux has separate child and buffering limits.
With TLS, put TlsClient after StripeClient and TlsServer before StripeServer.

This composition can improve upload/download throughput when the inter-server
limit applies independently to each TCP connection and aggregate capacity is
available. It cannot increase a shared link, per-IP or service limit. Children
share ordering delays within their group; losing any carrier ends the group and
its children. A normal child close does not close its siblings.

Mux opens a service connection after the child's first application payload.
Use the Stripe-only variant for services that send greetings first. The
[client reference](../ConnectionStripeClient/description.md#per-connection-bandwidth-limits-and-mux)
explains connection counts and the
[complete TLS example](../../WaterWall-Docs/docs/03-examples/tunnels/connection-stripe-tls.mdx) includes
both configurations.

## Configuration

```json
{
  "name": "stripe-server",
  "type": "ConnectionStripeServer",
  "next": "destination",
  "settings": {
    "max-connections": 32
  }
}
```

### Top-level fields

| Field | Requirement |
| --- | --- |
| `name` | Required node name, unique within the configuration. |
| `type` | Exactly `"ConnectionStripeServer"`. |
| `next` | Required, nonempty name of the application-side entry node. |
| `settings` | Optional object; omitted settings use the defaults below. |

### Settings

All settings are optional; provided values must be integers, not strings,
booleans, fractions or null. If `settings` is supplied, it must be an object.

| Setting | Default | Meaning |
| --- | --- | --- |
| `max-connections` | `32` | Largest accepted member count per application group, from `1` to `32`. This is not a total session limit. |
| `receive-window-bytes` | `1048576` | Maximum unconsumed bytes advertised to the peer, from `16384` to `16777216`. |
| `max-buffered-bytes` | `4194304` | Independent byte and allocation-charge limits for the pending application FIFO and each member's frame parser, from `65536` to `67108864`. |
| `setup-timeout-ms` | `10000` | Deadline for completing an incoming transport group, from `1` to `600000` milliseconds. |
| `drain-timeout-ms` | `10000` | Deadline for completing an orderly protocol close, from `1` to `600000` milliseconds. |
| `max-sessions` | `1024` | Maximum simultaneously retained sessions on each worker, from `1` to `65536`. |
| `max-pending-connections` | `1024` | Maximum transport lines waiting for a complete JOIN on each worker, from `1` to `65536`. |

Unknown or repeated setting names reject startup. Timeouts use a worker-local
one-second expiry sweep, so small millisecond values do not provide precise
subsecond closure. The drain deadline starts at the first local Finish or peer
CLOSE and is not extended by later progress.

The client selects each group's count with `connections`; the server validates
that it does not exceed `max-connections`. Local receive windows may differ.

## Understanding the limits

`max-connections: 32` accepts a client's group of eight; it does not wait for 32
members or create 32 destination connections. Every complete group creates one
application line through `next`. With a `TcpConnector` there, 100 groups of eight
use 800 incoming transport connections and 100 destination connections.

The server's `receive-window-bytes` controls **upload** credit for the entire
group. The client's corresponding setting controls **download** credit. Neither
window is multiplied by the member count. The fixed 256-record cap also applies;
at 16 KiB per record, no more than 4 MiB of DATA can be outstanding even if the
byte window is larger.

The server's pending application FIFO contains download data awaiting transport
capacity or client credit. `max-buffered-bytes` bounds that FIFO and each
transport parser independently. Receive reordering, transport buffers and other
groups have separate storage; this setting is not a total memory budget.

`max-pending-connections` counts individual incoming lines **before their JOIN
is complete**. Once a valid JOIN attaches a line to a group, that line leaves
the pending count. `max-sessions` counts groups, including incomplete groups and
groups still draining. Both admission limits apply per worker; a worker can
reach its limit while another still has capacity.

## Grouping and workers

Every member introduces a random 128-bit session ID, its unique index, the
expected member count and the client's receive window. The server rejects
duplicate indices and inconsistent introductions. Incomplete groups expire at
their setup deadline. The group remains registered while active, preventing a
late introduction from creating another application line for that group.

A keyed hash of the full session ID selects one worker. PipeTunnel moves member
processing to that worker when necessary; each original transport keeps its
correct return path. The server owns the reconstructed application line and
borrows the incoming transport lines.

The application line inherits member zero's source address context, including
its IP and port, before the next node is initialized. Worker handoff preserves
that context so downstream source-IP routing and limiting see the same values.

After every member is present, the server initializes exactly one application
line through `next` and sends READY. Setup requires no application payload,
allowing destinations that speak first on a direct application path. With Mux,
each service connection still waits for the child's initial payload. The client
and server nodes remain in the callback path throughout the session to map
distinct lines, framing, pressure and closure.

## Ordered transfer and bounded storage

Upload and download have independent byte offsets and record indices. DATA
records carry at most `16384` bytes. The receiver releases only contiguous data
and advertises aggregate credit across the group. The peer may have at most the
advertised number of unconsumed bytes and `256` DATA records outstanding.

Received out-of-order data occupies bounded receive storage. Unsent application
data uses a separate FIFO with both logical-byte and allocation-charge limits
given by `max-buffered-bytes`. The receive window is not a promise about total
process memory; transport nodes and the application have their own buffers.

The sender distributes records among writable members and skips paused members.
A slow connection can still hold up delivery when it carries the next missing
bytes. Application pressure delays delivery and new receive credit while control
traffic remains available to settle the protocol.

## Close and limitations

Finish closes the application line as a whole; there is no separate TCP
half-close API. CLOSE identifies the final byte and record counts. Its
acknowledgment follows in-order consumption of all preceding records, even if
CLOSE arrives first on another member.
The detached application line is not used again while the protocol drains.
Incoming reverse data after local Finish is consumed and discarded because that
application has already ended. A drain deadline bounds that work. Unexpected
loss of any member aborts the whole session; group members do not retransmit
each other's lost data.

The session ID provides grouping, not authentication or encryption. Configure
security nodes on the transport path as needed. Using several connections can
help fill available capacity, but cannot increase a shared link's capacity. With
a direct TcpConnector the destination side is one connection per group; with
MuxServer it is one connection per child.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| Incoming connections appear, but no destination connection is created | The server waits for all distinct members. Check that every member reaches this instance, the client's count fits `max-connections`, and the preceding transport decodes the expected stream. |
| A connection or incomplete group disappears after setup | Check its setup deadline and admission limits. A partial JOIN consumes a pending-connection slot; a complete JOIN waiting for its siblings consumes a session slot. |
| Only upload or download stalls | Check the receiving application's pressure and the receiving Stripe node's window for that direction. A missing earlier record can also hold up later records from healthy members. |
| Increasing the worker count does not accelerate one stream | Each group is reconstructed on one worker. Additional workers can process other groups; they do not split one group's reassembly. |

## Node Metadata

Source-backed values from `instance/node.c` and the shared framing constants:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagBlocksSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `24` bytes (`kStripeHeaderSize`) |

`can_have_next` describes topology capability; this node's constructor requires
`next`. Splice is disabled for chains containing this node. Its internal
PipeTunnel handles worker handoff and does not change the configured node's
layer requirements or application-side `next`.

See the [complete TLS example](../../WaterWall-Docs/docs/03-examples/tunnels/connection-stripe-tls.mdx)
and runnable configurations [with Mux](../ConnectionStripeClient/examples/tls-mux)
or [without Mux](../ConnectionStripeClient/examples/tls).
