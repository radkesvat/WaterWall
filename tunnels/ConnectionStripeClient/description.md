# ConnectionStripeClient

`ConnectionStripeClient` carries one application stream over several independent,
full-duplex transport connections. `ConnectionStripeServer` joins those connections
and reconstructs one ordered stream toward the destination. Upload and download
are striped independently; every transport can carry data in both directions.

```text
Client: TcpListener -> ConnectionStripeClient -> TlsClient -> TcpConnector
                                             == 8 TLS/TCP connections ==>
Server: TcpListener -> TlsServer -> ConnectionStripeServer -> TcpConnector
```

Both nodes operate on reliable layer-4 streams. Each input stream creates its
own transport group through the client's shared `next` path. That stream can be
one application connection or a shared Mux parent, as described below. Placing
`TlsClient` after this node gives each member its own TLS connection. All members
must reach the same `ConnectionStripeServer` instance in one WaterWall process.

## Transport placement

Every member opens a separate line through the same client `next` path.
The corresponding server transport must decode that path before handing bytes
to `ConnectionStripeServer`:

| Transport | After `ConnectionStripeClient` | Before `ConnectionStripeServer` |
| --- | --- | --- |
| TCP | `TcpConnector` | `TcpListener` |
| TLS over TCP | `TlsClient -> TcpConnector` | `TcpListener -> TlsServer` |
| KCP over UDP | `KcpClient -> UdpConnector` | `UdpListener -> KcpServer` |

Direct UDP does not provide the required reliable byte stream. Striping also
does not preserve application message or datagram boundaries; add appropriate
framing if the application needs them. There are no `upload`, `download` or
per-member path settings. See [ConnectionStripeServer](../ConnectionStripeServer/description.md)
for the matching server configuration.

## Per-connection bandwidth limits and Mux

ConnectionStripe can improve upload or download throughput when each TCP
connection between two servers has an independent bandwidth limit and the path
has unused aggregate capacity. For example, eight connections each limited to
10 Mbit/s have a theoretical combined capacity of 80 Mbit/s in the limited
direction, before overhead. This is an illustrative calculation, not a benchmark
or a guaranteed speedup. A shared link limit, a per-IP aggregate limit or service
capacity still bounds throughput.

To let multiple application connections share those carriers, place `MuxClient`
before Stripe and `MuxServer` after reassembly:

```text
Server 1: TcpListener -> MuxClient -> ConnectionStripeClient -> TcpConnector
Server 2: TcpListener -> ConnectionStripeServer -> MuxServer -> TcpConnector(service)
```

Mux combines application connections into shared parent streams. Stripe carries
**each Mux parent over its own group**; the remote MuxServer opens a separate
service connection for each child. With `K` active Mux parents and
`connections: N`, the transport uses `K × N` connections between the servers.
Mux mode, worker count and parent replacement affect `K`; `connections: 8` is
not a process-wide limit. Mux children share their group's receive window.

For a small example, use MuxClient mode `fixed-connections-count` with
`per-worker-connections-count: 1` and one client worker. Applications then reuse
one healthy selectable parent and its eight-member group. A single child's
normal close leaves siblings usable. A slow Stripe member can delay every child
on that parent, and losing any member aborts the group and ends those children.
Other groups remain independent.

**Mux opens a child at the service only after its first application payload.**
Use the Mux example for client-first protocols such as HTTP. For a service that
sends a greeting before the client writes, use the Stripe-only chain. Mux does
not carry a destination address per child; the shown connector targets one fixed
service. See the [MuxClient reference](../MuxClient/description.md) for its separate limits.

For TLS, put `TlsClient` between StripeClient and TcpConnector, and `TlsServer`
between TcpListener and StripeServer. The
[complete example](../../WaterWall-Docs/docs/03-examples/tunnels/connection-stripe-tls.mdx) provides
paired configurations with and without Mux.

## Configuration

```json
{
  "name": "stripe-client",
  "type": "ConnectionStripeClient",
  "next": "tls-client",
  "settings": {
    "connections": 8
  }
}
```

### Top-level fields

| Field | Requirement |
| --- | --- |
| `name` | Required node name, unique within the configuration. |
| `type` | Exactly `"ConnectionStripeClient"`. |
| `next` | Required, nonempty name of the shared transport entry node. |
| `settings` | Required object containing `connections`; other settings are optional. |

### Settings

Settings are integers; strings, booleans, fractions and null are rejected.

| Setting | Default | Meaning |
| --- | --- | --- |
| `connections` | Required | Number of transport connections per input stream (one application or Mux parent), from `1` to `32`. |
| `receive-window-bytes` | `1048576` | Maximum unconsumed bytes advertised to the peer, from `16384` to `16777216`. |
| `max-buffered-bytes` | `4194304` | Independent byte and allocation-charge limits for the pending application FIFO and each member's frame parser, from `65536` to `67108864`. |
| `setup-timeout-ms` | `10000` | Deadline for completing the transport group setup, from `1` to `600000` milliseconds. |
| `drain-timeout-ms` | `10000` | Deadline for completing an orderly protocol close, from `1` to `600000` milliseconds. |
| `max-sessions` | `1024` | Maximum simultaneously retained sessions on each worker, from `1` to `65536`. |

Unknown or repeated setting names reject startup. Timeouts use a worker-local
one-second expiry sweep, so small millisecond values do not provide precise
subsecond closure. The drain deadline starts at the first local Finish or peer
CLOSE and is not extended by later progress.

The server may choose a different receive window. Each sender honors the window
advertised by its receiver and also limits outstanding DATA records to `256`.

## Choosing counts and limits

`connections` applies **per input stream**. Without Mux, 100 active application
connections with `connections: 8` require 800 transport connections; with a direct
server-side TcpConnector they create 100 destination connections. Stripe itself
does not pool groups. With Mux before Stripe, application connections instead
share the groups of their Mux parents. `connections: 1` still uses the Stripe
protocol and requires `ConnectionStripeServer`; it does not bypass framing.

Use a count of one as a comparison point, then compare larger counts with the
same workload. Increasing the count adds transport handshakes and buffering;
it does not change the group's receive window or guarantee a throughput gain.

| Direction | Setting that limits the receiver's advertised byte credit |
| --- | --- |
| Upload: client to server | `receive-window-bytes` on `ConnectionStripeServer`. |
| Download: server to client | `receive-window-bytes` on `ConnectionStripeClient`. |

The byte window is shared by the whole group in that direction, not multiplied
by `connections`. The independent 256-record limit remains in force; with full
16 KiB records it permits at most 4 MiB of outstanding DATA, even with a larger
byte window. `max-buffered-bytes` instead bounds local unsent application data
and each member's parser separately. It is not a total process-memory limit.

`max-sessions` counts groups on each worker, including groups still setting up
or draining. One group stays on one processing worker at each endpoint; adding
members does not spread that group's reassembly across CPU workers.

## Setup, flow and close

Setup starts during line initialization, without waiting for the application's
first payload. Every transport sends a JOIN containing the same fresh random
128-bit session ID, its index, the group count and the client's receive window.
The server creates its application connection after every member has joined.
Without Mux on the application path, destinations that send the first bytes
are supported; Mux still waits for each child's initial payload.
Server data may reach the client on another member before READY arrives; it is
retained within the receive bounds until READY allows application delivery.

Transport establishment notifications remain separate from group readiness.
Application data arriving during setup is retained within the configured FIFO
limits. Once ready, the sender divides data into records of at most `16384` bytes,
selects writable transports, and skips paused members. The receiver uses offsets
to release data in the original order. A slower member can delay delivery of
later data that has already arrived on other members.

Backpressure combines transport availability, pending local data and the peer's
aggregate receive credit. Credit counts application bytes across the complete
group, so a blocked gap cannot cause unbounded reordering storage. Exhausting a
hard storage limit closes the session instead of dropping stream bytes.

Finish closes the application line as a whole; this node does not expose a
separate TCP half-close API. An orderly application Finish sends a CLOSE with
the final byte and record counts. The peer acknowledges it after consuming all
preceding records in order.
The protocol can retain its transport group while this bounded drain completes;
it does not continue calling the detached application line. Incoming reverse
data after local Finish is consumed and discarded because its application has
already ended. Losing any transport unexpectedly aborts the entire group. There
is no reconnection or retransmission between group members.

## Performance and security

Several transports can improve throughput when one connection underuses the
available network capacity. They do not multiply a shared bottleneck's bandwidth.
Striping applies only between the two Stripe nodes. With a direct TcpConnector,
each group has one destination connection; with MuxServer, each child has its own
destination connection. More members consume more sockets, TLS sessions and
buffering. Mux and Stripe add framing and share an ordered stream, so throughput
and latency should be compared with the same workload.

Session IDs identify groups; they do not authenticate peers or encrypt payloads.
Use security nodes on the transport path when those properties are needed.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| Transport connects, but the application receives no data | Every member must join the same Stripe server before the group becomes ready. Check the remote transport chain, server `max-connections`, setup deadline and destination connection. Transport Est alone does not mean the group is ready. |
| Increasing `connections` does not improve throughput | Check the shared link, destination connection, slowest member and CPU load. Each group has one reassembly worker and can fall back to ordinary buffers. |
| The application closes when a member disconnects | This is the whole-group failure policy. Check that member's transport errors and timeouts; remaining members do not replace it. |
| Sessions close under load | Check per-worker session admission, local queue/parser limits, and the neighboring transport's own limits. A larger receive window does not increase those separate limits. |

## Node Metadata

Source-backed values from `instance/node.c` and the shared framing constants:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `24` bytes (`kStripeHeaderSize`) |

`can_have_next` describes topology capability; this node's constructor requires
`next`. Both directions accept ordinary, pipe-backed splice, and mixed input.
DATA can retain its private pipe through framing and receive reordering when
`misc.splice` is enabled and every node in the expanded chain supports splice.
Plain TCP and Mux/TCP can use this path. TLS and KCP still block splice for their
entire chains, including the existing TLS examples. JOIN worker replay, bounded
storage canonicalization, and pipe checkout or transfer refusal can copy to
ordinary storage immediately. Splice support does not establish a throughput or
CPU improvement; performance remains unmeasured.

See the [complete TLS example](../../WaterWall-Docs/docs/03-examples/tunnels/connection-stripe-tls.mdx)
and runnable configurations [with Mux](examples/tls-mux)
or [without Mux](examples/tls).
