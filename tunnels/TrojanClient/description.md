<!--
Documentation version: 162
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TrojanClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/TrojanClient.mdx, and all files must keep the same documentation version.
-->

# TrojanClient Node

`TrojanClient` is a client-side Trojan protocol middle tunnel for Waterwall.

It sends the Trojan password line and request header expected by `TrojanServer`, then forwards normal application
payload. It supports TCP `CONNECT` and UDP `UDP ASSOCIATE`. For UDP, the node keeps the application line as a UDP line
and creates an internal TCP carrier line for Trojan UDP packets.

## Typical Placement

TCP Trojan client chain:

`TcpListener <-> TrojanClient <-> TlsClient <-> TcpConnector`

UDP Trojan client chain:

`UdpListener <-> TrojanClient <-> TlsClient <-> TcpConnector`

Mixed TCP/UDP client chain:

`TcpUdpListener <-> TrojanClient <-> TlsClient <-> TcpConnector`

Important:

- `TrojanClient` does not create or manage TLS.
- A normal Trojan deployment should place `TlsClient` after `TrojanClient`.
- The connector after `TlsClient` should connect to the Trojan server, usually with a constant server address and port.
- The final target destination is encoded inside the Trojan request or Trojan UDP packet.
- `TrojanClient` can use fixed JSON target values or the incoming `line->dest_ctx`.

## TCP Example

```json
{
  "name": "trojan-client",
  "type": "TrojanClient",
  "next": "tls-client",
  "settings": {
    "password": "secret-password",
    "address": "example.com",
    "port": 443,
    "protocol": "tcp",
    "dns-behaviour": {"resolve": false},
    "verbose": false
  }
}
```

This sends:

```text
hex(SHA224("secret-password")) CRLF CONNECT example.com:443 CRLF
```

The next nodes should carry that stream to the Trojan server, for example:

```text
TrojanClient -> TlsClient -> TcpConnector
```

## Destination-Context Example

```json
{
  "name": "trojan-client",
  "type": "TrojanClient",
  "next": "tls-client",
  "settings": {
    "sha224": "7e240de74fb1ed08fa08d38063f6a6a91462a815c15d3f6abf1d7e0b",
    "address": "dest_context->address",
    "port": "dest_context->port",
    "protocol": "dest_context->protocol"
  }
}
```

Use `sha224` when the configuration should contain the already-computed 56-character SHA224 hex digest instead of the
raw password.

## UDP Example

```json
{
  "name": "trojan-client-udp",
  "type": "TrojanClient",
  "next": "tls-client",
  "settings": {
    "password": "secret-password",
    "address": "dest_context->address",
    "port": "dest_context->port",
    "protocol": "udp"
  }
}
```

## Domain Resolution Example

```json
{
  "name": "trojan-client",
  "type": "TrojanClient",
  "next": "tls-client",
  "settings": {
    "password": "secret-password",
    "address": "example.com",
    "port": 443,
    "protocol": "tcp",
    "dns-behaviour": {"resolve": true, "strategy": "prefer-ipv4"}
  }
}
```

With this setting, `TrojanClient` resolves `example.com` before sending the Trojan request. If an IPv4 answer is
available, the request encodes that IPv4 address instead of the domain name. If no IPv4 answer is available, it falls
back to IPv6.

In UDP mode:

- the application line remains UDP-facing toward the previous node
- `TrojanClient` creates one internal TCP carrier line for that UDP application line
- the carrier sends a Trojan `UDP ASSOCIATE` request with `0.0.0.0:0`
- each upstream UDP payload is wrapped as `ATYP ADDR PORT LEN CRLF PAYLOAD`
- each downstream Trojan UDP packet is parsed, validated, stripped, and forwarded back as raw UDP payload

## Required JSON Fields

- `settings.password` or `settings.sha224`
  Authentication material for the Trojan password line.

  `password` is the raw password. `TrojanClient` calculates `SHA224(password)` and sends the lower-case hex form.

  `sha224` is the already-computed 56-character hexadecimal SHA224 digest.

- `settings.address`
  The final target host or IP to encode in the Trojan request. Accepted aliases are `target-address`, `address`, and
  `target`. It may be a literal host/IP or `"dest_context->address"`.

- `settings.port`
  The final target port to encode in the Trojan request. It may be a number or `"dest_context->port"`.

## Optional JSON Fields

- `settings.first-payload-timeout-ms`
  Integer milliseconds from 0 through 4,294,967,295; default 400. Zero disables deliberate waiting.

- `settings.protocol`
  Selects the Trojan command and the protocol placed in `line->dest_ctx`.

  Supported values:

  - `"tcp"` or `"connect"`
    Send a Trojan TCP `CONNECT` request.
  - `"udp"` or `"udp-associate"`
    Send a Trojan UDP association request and carry UDP datagrams over the internal TCP carrier.
  - `"dest_context->protocol"` or `"line->dest_ctx->protocol"`
    Use the incoming destination context protocol. Exact TCP selects `CONNECT`; exact UDP selects `UDP ASSOCIATE`.

  If `dest_context->protocol` is selected but the incoming protocol is missing, ambiguous, or not TCP/UDP,
  `TrojanClient` logs a warning and falls back to TCP.

  Default: `"tcp"`

- `settings.verbose`
  Enables extra tunnel logging.

- `settings.dns-behaviour`
  Controls local target lookup, address selection and DNS transport. See DNS behaviour below.

## DNS behaviour

Resolving a hostname means looking up its IP address. `TrojanClient` can send
the final target's hostname in the Trojan request, or resolve it locally and
send the selected IP instead. Local resolution runs only for an unresolved
hostname when enabled. Literal IPs and already-resolved targets need no lookup.

This setting concerns the final target reached through the proxy. The following
connector selects the proxy server's address and has its own DNS settings.
Without `dns-behaviour`, local resolution is disabled.

Configure this lookup with `settings.dns-behaviour`:

```json
{
  "dns-behaviour": {
    "resolve": true,
    "mode": "direct",
    "strategy": "prefer-ipv4",
    "servers": ["203.0.113.53:53"]
  }
}
```

The address is a documentation placeholder; replace it with your resolver.

| Field | Meaning |
| --- | --- |
| `resolve` | Required boolean: `true` allows lookup of unresolved hostnames; `false` disables local lookup. |
| `mode` | `native` (default when enabled), `direct`, or `chain`. |
| `strategy` | `core-settings`, `accept-dns-returned-order`, `prefer-ipv4`, `prefer-ipv6`, `only-ipv4`, or `only-ipv6`; omission uses this consumer's default address preference. |
| `servers` | 1–32 numeric IP, IP:port or [IPv6]:port endpoints; required for direct/chain and rejected for native. |
| `dns-next` | Nonempty DNS-entry name for chain only. |

`native` uses core DNS settings and the worker's shared resolver. It is the default
DNS transport when local resolution is enabled.

`direct` sends DNS queries through a private WaterWall TCP/UDP connector to the
servers you specify.

`chain` sends DNS queries through a selected chain. Use a path with encryption,
such as your VPN, to protect those queries; the mode alone does not encrypt them.
The DNS path must carry both UDP queries and TCP fallback. A route or lookup
failure does not switch to native DNS or another mode.

In `chain` mode, omitting `dns-next` sends DNS requests through this proxy client
and its following transport. To use another path, set `dns-next` to a separate
DNS branch that does not already belong to another node. Leave the field omitted
to use this node; do not set it to this node's own name.

The disabled form is exactly `"dns-behaviour": {"resolve": false}`. It rejects `mode`, `strategy`, `servers` and `dns-next`. Empty/null/non-object policies, unknown fields and numeric strategies are rejected. Strategy names use the canonical lowercase strings above. `core-settings` chooses address preference only and never changes DNS transport.

`resolve: false` keeps the hostname in requests that support it. The following connector still selects the independent proxy/VPN endpoint and has its own DNS policy. Use a numeric outer endpoint or an independent bootstrap path.

See [DomainResolver](../../WaterWall-Docs/docs/02-noderefs/DomainResolver.mdx) for native, direct and protected-chain configuration examples and core option limits. This policy controls lookups owned by this node; it does not configure PTC fake DNS, TunDevice system DNS or every DNS source in the program.

## First payload and transport establishment

`Init` prepares the destination and starts the next node without emitting a request.
The first eligible application payload may arrive before transport `Est`, during its
callback, or after Pause. It is sent immediately with the complete request
in one ordinary buffer, including one UDP frame header when applicable. Ordinary input
is reused in place when its headroom fits all headers. Otherwise a best-fit ordinary
buffer is allocated; any resident prefix and private-pipe body are copied in order.
Empty TCP input does not trigger a request. Empty Trojan UDP datagrams are valid.

Direct TCP transport `Est` reaches the live application promptly, including repeated
notifications, independently of protocol data and Pause. UDP carrier establishment
maps once to its application. If the request remains unsent, its first-payload
deadline starts at the first Est.
`settings.first-payload-timeout-ms` defaults to **400**, accepts integers from **0** to
**4,294,967,295**, and rejects other types and ranges. Zero disables deliberate waiting.
Paused time counts. On direct TCP, expiry sends one header-only request even after
Pause; all Pause/Resume notifications pass through, including duplicates, without
retaining consumer-pause state. On an owned UDP carrier, the client is the exact-line
head and retains producer control: an idle header due during carrier Pause waits for
Resume. An eligible payload arriving first cancels the timer and sends the combined
output. Duplicate Est/Resume cannot repeat the request or reset its deadline. Finish
cancels the timer.
One ordinary output does not promise one syscall, TCP packet, or TLS record.

Direct TCP and per-datagram upstream forwarding do not wait for Est or Resume and do
not keep application output queues. Trojan has no success response; downstream TCP is opaque from Init.
Once the complete initial TCP request is ready, the client destroys its setup state,
cancels the timer and permanently bypasses itself before handing off that buffer.
All later callbacks follow the same line directly through the neighbouring tunnels.
Reentrant Est continuations check that the client is still active before
accessing its state. UDP application and carrier lines remain active for framing,
signal mapping and owned-carrier cleanup.

UDP application lines remain borrowed UDP-facing lines. The client creates one dependent,
owned TCP carrier on the application's worker and maps Est, Pause/Resume and Finish to
that association. The request uses `0.0.0.0:0`; each frame encodes its destination, length and CRLF.
The UDP decoder finishes every complete datagram in an admitted input even when an earlier
delivery causes Pause. Nested input joins the guarded parser FIFO behind older input;
only incomplete framing/order state remains. Finish, malformed input or receiver refusal
stops delivery and closes the affected association. Only this node's owned carrier is
destroyed here; the application owner drains it during shutdown.

## Splice and retention

The first request plus payload is ordinary; the request itself is at most 320 bytes.
Later opaque TCP preserves its original ordinary or splice representation. UDP sends
prepend at most 263 bytes within the advertised 331-byte padding budget. Header parsing and exact body
movement preserve boundaries and use complete ordinary fallback when padding or pipe
capacity requires it. Receive extraction preserves full onward padding.

| Retained parser input | Inclusive logical limit |
| --- | --- |
| UDP wire input, including active head and cached header | 2,162,950 bytes (2 MiB plus one 65,798-byte maximum frame) |
| UDP body | 65,535 bytes; empty bodies are valid |

Equality passes; overflow or parser queue refusal closes the association. There is no
retained decoded-output queue or 1,024-record limit on a synchronous batch. Fragment
counts do not consume output slots. These are logical protocol limits, independent
of buffer-pool size, RAM profile, and pipe capacity. Oversized local datagrams are
dropped; malformed received frames close the association. Received source addresses are validated without changing the application destination.

The two-byte body length supports 0 through 65,535 payload bytes in either direction;
the address, length and CRLF add up to 263 bytes outside that body. This is a Trojan
framing limit, not a guarantee that a UDP socket or remote peer accepts every size.
For example, ordinary IPv4 UDP permits at most 65,507 payload bytes without IP
options, and a path or peer may impose a lower limit. Each accepted payload remains
one datagram: TCP may split the encoded frame into reads, but Trojan never truncates
the payload or turns it into several application datagrams.

UDP receive storage is compacted when the active head and queued input exceed
8 MiB of queue-capacity charge or 1,024 retained buffers. Complete accepted frames
drain first; incomplete input and nested input settle before returning. Compaction
preserves byte order and cached headers. These thresholds do not limit how many
fragments a valid datagram may contain. If compact storage cannot fit the charge
allowance, the association closes and releases its retained input.

Splice requires `misc.splice`, a supported build and support from every node in the
final chain, including internal helpers. `DomainResolver` supports splice. `TlsClient`
still blocks splice for its entire chain. Keep TLS in ordinary deployment configurations;
splice capability does not guarantee zero-copy or a measured speed increase.

## Notes And Caveats

- `TlsClient` is required for ordinary Trojan compatibility and probe resistance, but it is not inserted automatically.
- `TrojanClient` does not implement server fallback behavior; fallback is a server-side feature.
- outbound UDP payloads larger than 65,535 bytes cannot fit the length field and are dropped without killing the
  whole local association. Incoming frames accept the full two-byte body-length range.
- `required_padding_left` is 331 bytes, covering the initial UDP association request plus its first datagram header.
  Later datagrams prepend only their frame header, at most 263 bytes.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `331` bytes |
