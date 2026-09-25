# StreamFragmenter

`StreamFragmenter` splits selected upstream TCP payload callbacks into ordered
byte ranges and delays their delivery. It is a configurable internal Layer 4
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
| `cuts` | Required array of at most 64 entries, each exactly `[offset, delay_ms, chance_percent]`. |

Offsets are strictly increasing integers in `1..4294967295`. Delays are integers
in `0..4294967295` milliseconds; chances are integers in `0..100`. Invalid types,
unknown or duplicate settings, and invalid ordering reject construction. There
are no string duration formats. Zero count, zero duration, or an empty cut array
disables shaping immediately. All settings are validated even when shaping is
disabled.

## Selection and timing

Each line has independent eligibility. Counter mode counts every upstream
Payload arrival, including empty, bypassed, too-short, and uncut payloads. Timed
mode starts at this node's upstream Init and accepts arrivals strictly before its
monotonic deadline. Eligibility and random selections are fixed at arrival,
even if a job waits beyond that deadline.

For each eligible payload, bypass is evaluated first. Otherwise every applicable
cut receives an independent percentage roll. A cut applies only when its offset
is strictly inside that original payload. No selected cuts means unchanged
forwarding. Zero and one hundred percent have exact outcomes.

With a 1,000-byte payload and both example cuts selected, the output is:

```text
wait 2 ms; send [0,250)
wait 5 ms; send [250,300)
           send [300,1000)
```

A job's first delay starts when it becomes the active FIFO head. Later delays
start after the previous fragment's actual handoff. Time spent behind older jobs
does not satisfy a later job's delay. Zero-delay fragments and the final suffix
are sent immediately when the consumer permits. Scheduling can make delivery
late, but the node checks monotonic deadlines so timer rounding cannot shorten
the configured delay.

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

The node advertises splice support with zero extra prepend padding. Unchanged
payloads retain their representation. Selected ranges use the existing buffer
range helpers: ordinary prefixes are copied into padded pooled output; splice
bodies move between private pipes where possible, with ordinary-memory fallback
when a destination pipe cannot be obtained or filled. The final remainder is
handed onward directly. No generic byte accessor reads pipe metadata as payload.

Only one delay timer is published per line. All state, timers, and buffer
recycling belong to that line's event worker. Callback continuations hold a line
reference and stop after logical death. Generic worker quiescence detaches timers
before owner-line drain releases retained buffers and timer handles.
