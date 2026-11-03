# QuicClient

`QuicClient` encrypts upstream application bytes into a raw QUIC stream and
decrypts downstream carrier datagrams back into application bytes. Google
QUICHE performs the real QUIC v1/TLS 1.3 handshake, packet cryptography, loss
recovery and congestion control. The node opens no socket and resolves no
transport destination; configure the following carrier separately.

```text
TcpListener -> QuicClient -> UdpConnector
SpeedTestClient -> VlessClient -> QuicClient -> UdpConnector
```

## Example

```json
{
  "name": "quic-client",
  "type": "QuicClient",
  "next": "carrier-out",
  "settings": {
    "sni": "quic.example.test",
    "verify": true,
    "ca-file": "server.crt",
    "protocol": "h3",
    "carrier-mode": "datagram"
  }
}
```

`name`, `type`, `next` and an object `settings` are required. `type` must be
exactly `QuicClient`. Full UDP and framed TCP client/server configurations and
local certificate instructions are in
[`tunnels/QuicClient/examples`](https://github.com/radkesvat/WaterWall/tree/main/tunnels/QuicClient/examples).

## Client settings

| Setting | Default | Behavior |
| --- | --- | --- |
| `sni` | Required | ASCII DNS/A-label server name, 1–253 bytes; used for TLS SNI and hostname verification. It does not resolve or replace the carrier destination. |
| `verify` | `true` | Boolean; verifies certificate chain, trust, validity period and hostname. Explicit `false` disables trust/name checks while retaining the encrypted handshake. |
| `ca-file` | Bundled trust roots | Optional PEM trust bundle. When supplied it replaces the bundled trust source. No network certificate fetch occurs. |

DNS names outside ASCII must be supplied as A-label/punycode. Unreadable or
malformed trust bundles fail startup. Certificate, hostname, ALPN and QUIC
version mismatch fail the connection without fallback.

## Shared settings

| Setting | Default | Accepted values and behavior |
| --- | --- | --- |
| `protocol` | `"h3"` | One exact, printable ASCII ALPN identifier, 1–255 bytes. Both peers must agree. |
| `carrier-mode` | `"datagram"` | Exactly `datagram` or `stream`. Select explicitly for a stream carrier. |
| `handshake-timeout-ms` | `10000` | Integer 1–86,400,000. Total deadline through authenticated handshake and application-stream opening; partial input does not restart it. |
| `idle-timeout-ms` | `60000` | Integer 1–86,400,000. QUIC idle lifetime, subject to peer negotiation and the carrier's own lifetime. |
| `close-drain-timeout-ms` | `30000` | Integer 1–86,400,000. Local delivery deadline from the first local application Finish or peer FIN, including before handshake readiness; it is not extended by progress or retries. |
| `max-packet-size` | `1350` | Integer 1200–1452. Maximum emitted QUIC datagram, excluding the stream envelope; input independently accepts up to 1,472 bytes. |
| `max-buffered-bytes` | `2097152` | Integer 65,536–67,108,864. Per-line bound for each independent retained application/output backlog, including accepted unacknowledged plaintext. |
| `max-buffered-buffers` | `1024` | Integer 1–65,536. Per-backlog entry bound, including active retention. |
| `receive-window-bytes` | `1048576` | Integer 16,384–16,777,216 and no greater than `max-buffered-bytes`; initial stream receive credit. |
| `verbose` | `false` | Boolean extra diagnostics; does not log plaintext, private keys or session secrets. |

Integers must be JSON integer tokens. Strings, booleans and fractional numbers do
not satisfy integer fields. Invalid values fail startup with a setting-specific
diagnostic. Set `receive-window-bytes` as well when reducing the byte budget
below its default.

Each configured entry reserves descriptor storage: require
`(max-buffered-buffers + 1) * 24 <= max-buffered-bytes`. A send ledger reserves
16 bytes per configured entry. Wire events reserve
`(max-buffered-buffers + 1) * 24` bytes and plaintext/control events reserve
`(max-buffered-buffers + 2) * 24` bytes for payload descriptors and the
READY/PEER_FIN/CLOSED controls. These backing charges count toward allocation
budgets even while the rings are empty; closing releases them.

## Carrier and application semantics

The application interface is a reliable byte stream. Application Payload buffer
boundaries are not preserved. Each association has one QUIC connection and one
client-initiated bidirectional stream. `QuicClient` borrows the application's
normal line and owns a separate carrier line. `QuicServer` borrows the carrier's
normal line and owns a separate service line. This separates application closure
from the lifetime needed for delivery and acknowledgements. Adapters own their
sockets; each normal line is destroyed only by its creator.

In `datagram` mode, one carrier Payload is exactly one complete QUIC datagram,
with no private outer prefix. In `stream` mode every datagram has a four-byte
unsigned big-endian length followed by that many bytes. Both peers must select
`stream` over a byte-stream carrier. Its incremental parser accepts fragmented
prefixes/bodies and coalesced frames; zero lengths or lengths above 1,472 close
the association. There is no automatic carrier detection, fallback or adapter
insertion.

The client sends one encrypted opening byte `0x00` before application data. The
server consumes it internally, allowing a server-first application to send even
when the client has no application bytes. A real leading NUL in application
data remains intact. Extra application streams and the QUIC DATAGRAM application
extension are not exposed.

`protocol="h3"` announces ALPN only. The stream mapping is private raw QUIC,
with no HTTP/3 requests, responses, QPACK or HTTP control streams. Ordinary
HTTP/3 peers cannot use it. This setting makes no Chrome/Cloudflare
impersonation or classifier claim and does not change `HttpClient`/`HttpServer`.

## Flow, storage and close

Every supported transport `Est` is relayed promptly, including repeats;
authenticated handshake and stream readiness are independent internal barriers.
Before readiness, admitted application data waits in FIFO order under hard
budgets. Pause/Resume are advisory and relayed, including duplicates. QUIC loss
alarms, ACK processing and ordered ready output continue through advisory Pause.
Local send pressure asks only the application producer to pause when any
retained byte count, entry count or allocation charge exceeds three quarters
of its limit. It resumes only when all three fall below one half; equality
preserves the hold. The allocation limit is twice the byte budget. ACK-only
input can release accepted send storage and clear this pressure.

Configured byte and entry limits apply independently to the documented
backlogs. WaterWall-owned retained allocation charge is also bounded to twice
the associated byte budget. Accepted send chunks remain charged while
unacknowledged; a later ACK cannot bypass an earlier outstanding ledger entry.
These limits do not claim a hard cap on every QUICHE heap allocation.

An adjacent UDP adapter may stop reads during an external Pause, including
ACK ingress. A finite pause can recover; a sufficiently long pause may expire
QUIC deadlines. Both nodes block splice and do not implement connection pooling,
migration across carrier lines, NAT-rebinding reassociation, resumption or 0-RTT.

Application-side `Finish` immediately detaches the application and stops all
callbacks toward it. Both nodes retain the carrier and QUIC engine to deliver
already accepted bytes, then a stream FIN, under congestion control and loss
recovery. This also applies to application Finish before handshake readiness.
The first local application Finish or peer FIN starts the fixed local
`close-drain-timeout-ms` deadline. Handshake, idle, transport failure and process
shutdown can end the association sooner; retries and ACKs never restart it.

Receiving peer FIN delivers preceding decoded bytes, then finishes and detaches
the application. Already accepted output still drains before CONNECTION_CLOSE.
After the local FIN is acknowledged and peer FIN is received, the engine enters
QUIC closing/draining. Its separate fixed retention interval is at most three
probe timeouts (PTO), capped by `close-drain-timeout-ms`; it handles late close
traffic without reopening the application. Acknowledged payload bytes alone do not complete this phase;
FIN acknowledgement remains required. Expiry before confirmation
is logged as unconfirmed delivery. No finite timeout guarantees delivery through
an indefinitely unavailable network.

Carrier-side Finish and process shutdown abort outstanding delivery and settle
owned lines immediately. FIN closes the application association rather than
providing application half-close; a reset or other protocol failure also closes it.

## Node Metadata

Both nodes are Layer 4 transforms with separate application and carrier lines: they allow previous and next
nodes, advertise `kNodeFlagBlocksSplice`, and require zero additional left
padding. They do not inspect or reject neighboring adapter types. Google QUICHE
and its runtime dependencies are linked statically through the shared prefixed
BoringSSL provider.

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagBlocksSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `0` bytes |
