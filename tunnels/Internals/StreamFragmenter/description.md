# StreamFragmenter

`StreamFragmenter` delays selected upstream byte ranges or fragments the initial
TLS ClientHello into valid handshake records. It is a configurable internal Layer 4
middle node, built by default with `INCLUDE_STREAM_FRAGMENTER`.

```text
TcpListener -> StreamFragmenter -> TcpConnector
```

Place it at the point whose upstream bytes you want to shape. A payload is one
WaterWall callback, not a TCP packet, TLS record, or application message. Later
transforms and the transport can combine writes; the node does not promise wire
packet boundaries. Downstream bytes and transport establishment pass through.

## Configuration

```json
{
  "name": "fragmenter",
  "type": "StreamFragmenter",
  "next": "out",
  "settings": {
    "mode": "counter",
    "count": 3,
    "bypass_chance": 20,
    "cuts": [[250, 2, 50], [300, 5, 40]]
  }
}
```

For timed eligibility, replace `"mode": "counter", "count": 3` with
`"mode": "timed", "duration-ms": 100`.

| Setting | Contract |
| --- | --- |
| `mode` | Required; exactly `counter` or `timed`. |
| `count` | Required in counter mode, forbidden in timed mode; integer `0..4294967295`. |
| `duration-ms` | Required in timed mode, forbidden in counter mode; integer `0..4294967295`, in milliseconds. |
| `bypass_chance` | Optional integer `0..100`, default `0`. |
| `wait-for-est` | Optional boolean, default `true`; hold upstream payloads until the first downstream transport Est has been forwarded. |
| `tls-hello-fragment` | Optional boolean, default `false`; interpret cuts as initial ClientHello handshake offsets and rewrite TLS record framing. |
| `tls-hello-timeout-ms` | Optional integer `1..4294967295`, default `1000`; permitted only when TLS mode is true. |
| `cuts` | Required array of at most 64 entries, each exactly `[offset, delay_ms, chance_percent]`. |

Offsets are strictly increasing integers in `1..4294967295`. Delays are integers
in `0..4294967295` milliseconds; chances are integers in `0..100`. Invalid types,
unknown or duplicate settings, and invalid ordering reject construction. There
are no string duration formats. Zero count, zero duration, or an empty cut array
disables shaping and TLS probing immediately. All settings are validated even when shaping is
disabled. An enabled `wait-for-est` still holds input when shaping is disabled.

## Selection and timing

Each line has independent eligibility. Counter mode counts every upstream
Payload arrival, including empty, bypassed, too-short, and uncut payloads. Timed
mode starts at the first downstream Est by default, or at this node's upstream
Init when `wait-for-est` is `false`, and accepts arrivals strictly before its monotonic
deadline. Pre-Est arrivals remain eligible in timed mode with the startup wait;
counter mode still counts those arrivals normally. Eligibility and random
selections are fixed at arrival, even if a job waits beyond that deadline.

In default stream mode, for each eligible payload, bypass is evaluated first. Otherwise every applicable
cut receives an independent percentage roll. A cut applies only when its offset
is strictly inside that original payload. No selected cuts means unchanged
forwarding. Zero and one hundred percent have exact outcomes.

With a 1,000-byte payload and both example cuts selected, the output is:

```text
wait 2 ms; send [0,250)
wait 5 ms; send [250,300)
           send [300,1000)
```

A job's first delay starts when it becomes the active FIFO head and the startup
gate is open. Later delays
start after the previous fragment's actual handoff. Time spent behind older jobs
does not satisfy a later job's delay. Zero-delay fragments and the final suffix
are sent immediately when the consumer permits. Scheduling can make delivery
late, but the node checks monotonic deadlines so timer rounding cannot shorten
the configured delay.

### Initial TLS ClientHello records

Set `tls-hello-fragment: true` to apply `cuts` only to the initial ClientHello.
Offsets count handshake message bytes, including its four-byte type/length header
and excluding every five-byte TLS record header. An eligible first non-empty
arrival latches the choice for the line; later callbacks complete that candidate
even after `count` or the timed window expires. Empty callbacks still consume
counter scope. Detection never restarts for a later ClientHello. Cuts strictly
inside the declared handshake length are sampled once. If none is selected, the
original bytes flow without waiting for the full hello.

The node accepts handshake records with TLS version bytes `03 01`, `03 02`, or
`03 03`, a ClientHello message of 45 through 65,536 bytes, and a hello ending
at an original record boundary. It preserves each original record boundary and
version, adding a record boundary only where a selected cut falls inside an
existing record. Handshake bytes remain identical, including the message header;
TLS record headers and output timing can change. A cut already at an original
boundary still supplies its configured delay without adding a header. Each
scheduled piece can contain several TLS records, and transport writes do not
promise TCP segment boundaries.

Unsupported framing, non-TLS input, a hello over 64 KiB, a hello sharing its
final record with another message, bypass, or deadline expiry ends detection
and forwards the original wire bytes in order. The assembly deadline starts on
the first eligible non-empty arrival and includes time waiting for Est or Resume.
Its timer may run before Est or while paused; expiry keeps the original bytes
behind those output gates. A completed rewrite cannot later time out. Finish
discards incomplete input without a timeout replay. This option neither locates
SNI automatically nor applies independent TLS and TCP cut profiles.

### Waiting for transport establishment

By default (`wait-for-est: true`), all upstream input enters the existing bounded FIFO
before Est, including empty, bypassed and no-longer-eligible payloads. No fragment
delay starts and no upstream output is sent yet. TLS assembly can have its own
deadline timer during this wait. Downstream data and pressure signals continue
through their normal paths.

Set `wait-for-est: false` to allow scheduling and upstream delivery before Est.

The first downstream Est starts the timed eligibility window and is forwarded
immediately, including while paused. The startup gate remains closed during
that notification: nested Payload, Resume or Est cannot release data or start a
fragment-delay timer. After forwarding returns on the live line, scheduling begins at the FIFO
head. Duplicate Est notifications still forward but do not restart either the
eligibility window or fragment delays. Subsequent Pause/Resume retains the usual
elapsed-delay behavior.

This can keep configured delays from being consumed while a following TCP
transport connects. It requires a genuine downstream Est to release input; no
Est is synthesized and no separate startup timeout is added. Finish before Est
discards the FIFO. Further downstream buffering can still combine deliveries,
so this setting does not guarantee packet boundaries or spacing on the wire.

## FIFO, pressure, and shutdown

One FIFO owns all retained upstream payloads, including its active head. Bypassed
payloads and arrivals after eligibility ends remain behind older work. Once
eligibility ends and retained work drains, writable upstream traffic forwards
directly without allocating jobs or scheduling timers. Reentrant arrivals cannot
overtake an active job's remainder.

Consumer Pause stops upstream output. An armed timer keeps running; expiry while
paused leaves the due fragment queued, without polling or restarting its delay.
Resume releases due work. The next fragment's delay starts only after the
previous fragment is forwarded. Pause/Resume controlling downstream traffic
continue through the default callbacks.

The fixed per-line budget includes waiting jobs and the active remainder:

| Limit | Value |
| --- | --- |
| Hard capacity charge and logical bytes | 8 MiB |
| Hard payload-job count | 1,024 |
| Pause source | At 6 MiB capacity charge or 768 jobs |
| Release local pressure | At/below 3 MiB charge and 384 jobs |

Capacity charge uses WaterWall's buffer-budget accounting, including empty
buffers and retained ordinary allocation capacity. It is not an RSS or physical
kernel-pipe-memory limit. Job metadata is bounded by the job count. Fragment
extraction additionally uses one transient output buffer before transferring it
to the next node. Consumer and local pressure are combined: clearing one reason
cannot resume a source still held by the other.

Admission overflow or recoverable job/timer setup refusal closes this connection
in both directions. It never drops arbitrary TCP bytes while leaving the
connection open. A received Finish cancels the timer, discards all retained
payloads, clears local state, and forwards only away from its sender. There is
no delayed flush after Finish. The node borrows its normal line; its creator
owns line destruction and shutdown drain.

## Buffers and splice

The node advertises splice support with zero extra prepend padding. Later opaque
payloads retain their representation. Generic selected ranges use the existing buffer
range helpers: ordinary prefixes are copied into padded pooled output; splice
bodies move between private pipes where possible, with ordinary-memory fallback
when a destination pipe cannot be obtained or filled. The final remainder is
handed onward directly. TLS inspection materializes only a bounded prefix through
the same range helpers; later opaque splice wrappers can pass through unchanged.
No generic byte accessor reads pipe metadata as payload.

Only one timer is published per line, for either assembly or fragment delay. All state, timers, and buffer
recycling belong to that line's event worker. Callback continuations hold a line
reference and stop after logical death. Generic worker quiescence detaches timers
before owner-line drain releases retained buffers and timer handles.

## Acknowledgements

WaterWall's fragmentation features draw inspiration from:

- **[GFW-knocker](https://github.com/GFW-knocker/gfw_resist_tls_proxy)** — for practical work on splitting TLS
  ClientHello traffic into smaller TCP stream writes with delays, which inspired our stream fragmentation approach.
- **[patterniha](https://github.com/XTLS/Xray-core/issues/4370)** — for explaining and exploring TLS record
  fragmentation and its distinction from TCP fragmentation, which informed our TLS ClientHello record fragmentation
  feature.

We thank both developers for sharing their work with the community.
