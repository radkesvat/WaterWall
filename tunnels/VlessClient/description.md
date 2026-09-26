<!--
Documentation version: 159
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/VlessClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/VlessClient.mdx, and all files must keep the same documentation version.
-->

# VlessClient Node

`VlessClient` is a client-side plain VLESS v0 middle tunnel for Waterwall.

It sends a VLESS request header with a configured UUID and final target destination, forwards upstream application payload
without waiting for the VLESS response header, and validates the response header before delivering downstream body bytes.
It supports TCP command `0x01` and UDP command `0x02` with the base VLESS UDP length framing.

This node implements plain VLESS only. It does not create TLS, REALITY, XTLS Vision, flow addons, mux, XUDP, WebSocket,
gRPC, or other transport wrappers.

## Typical Placement

TCP VLESS client chain:

`TcpListener <-> VlessClient <-> TlsClient <-> TcpConnector`

UDP VLESS client chain:

`UdpListener <-> VlessClient <-> TlsClient <-> TcpConnector`

Important:

- `VlessClient` does not create or manage TLS.
- A normal VLESS deployment should place `TlsClient` after `VlessClient`.
- The connector after `TlsClient` should connect to the VLESS server, usually with a constant server address and port.
- The final target destination is encoded inside the VLESS request header.
- `VlessClient` can use fixed JSON target values or the incoming `line->dest_ctx`.

## TCP Example

```json
{
  "name": "vless-client",
  "type": "VlessClient",
  "next": "tls-client",
  "settings": {
    "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "address": "example.com",
    "port": 443,
    "protocol": "tcp",
    "domain-strategy": "do-not-resolve-domains",
    "verbose": false
  }
}
```

The next nodes should carry the byte stream to the VLESS server, for example:

```text
VlessClient -> TlsClient -> TcpConnector
```

## Destination-Context Example

```json
{
  "name": "vless-client",
  "type": "VlessClient",
  "next": "tls-client",
  "settings": {
    "id": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "address": "dest_context->address",
    "port": "dest_context->port",
    "protocol": "dest_context->protocol"
  }
}
```

`id` and `user-id` are accepted aliases for `uuid`.

## UDP Example

```json
{
  "name": "vless-client-udp",
  "type": "VlessClient",
  "next": "tls-client",
  "settings": {
    "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "address": "dest_context->address",
    "port": "dest_context->port",
    "protocol": "udp"
  }
}
```

In UDP mode:

- the application line remains UDP-facing toward the previous node
- `VlessClient` creates one internal TCP carrier line for that UDP application line
- the carrier sends a VLESS UDP request header containing the fixed final target
- each upstream UDP payload is wrapped as `uint16_be length + payload`
- each downstream VLESS UDP frame is length-decoded and forwarded back as raw UDP payload

## Domain Resolution Example

```json
{
  "name": "vless-client",
  "type": "VlessClient",
  "next": "tls-client",
  "settings": {
    "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "address": "example.com",
    "port": 443,
    "protocol": "tcp",
    "domain-strategy": "resolve-domains-and-prefer-ipv4"
  }
}
```

With this setting, `VlessClient` resolves `example.com` before sending the VLESS request. If an IPv4 answer is
available, the request encodes that IPv4 address instead of the domain name. If no IPv4 answer is available, it falls
back to IPv6.

## Required JSON Fields

- `settings.uuid`
  Authentication UUID for the VLESS request.

  Accepted aliases: `uuid`, `id`, and `user-id`.

  The value may be a dashed RFC4122 UUID string or compact 32-character hexadecimal UUID. It is sent as 16 raw bytes in
  RFC4122 text order, not as ASCII and not as a platform GUID structure.

- `settings.address`
  The final target host or IP to encode in the VLESS request. Accepted aliases are `target-address`, `address`, and
  `target`. It may be a literal host/IP or `"dest_context->address"`.

- `settings.port`
  The final target port to encode in the VLESS request. It may be a number or `"dest_context->port"`.

## Optional JSON Fields

- `settings.first-payload-timeout-ms`
  Integer milliseconds from 0 through 4,294,967,295; default 400. Zero disables deliberate waiting.

- `settings.protocol`
  Selects the VLESS command and the protocol placed in `line->dest_ctx`.

  Supported values:

  - `"tcp"` or `"connect"`
    Send VLESS TCP command `0x01`.
  - `"udp"` or `"udp-associate"`
    Send VLESS UDP command `0x02` and carry UDP datagrams over the internal TCP carrier.
  - `"dest_context->protocol"` or `"line->dest_ctx->protocol"`
    Use the incoming destination context protocol. Exact TCP selects command `0x01`; exact UDP selects command `0x02`.

  If `dest_context->protocol` is selected but the incoming protocol is missing, ambiguous, or not TCP/UDP,
  `VlessClient` logs a warning and falls back to TCP.

  Default: `"tcp"`

- `settings.verbose`
  Enables extra tunnel logging.

- `settings.domain-strategy`
  Controls whether `VlessClient` resolves domain targets before encoding the VLESS request destination.

  Default: `"do-not-resolve-domains"`.

  Supported values:

  - `"do-not-resolve-domains"`
    Keep domain targets as domains in the VLESS request. This lets the VLESS server side resolve the target domain.
  - `"resolve-domains-and-accept-dns-returned-order"`
    Resolve domain targets and use the first usable DNS result.
  - `"resolve-domains-and-prefer-ipv4"`
    Resolve domain targets, prefer IPv4, and fall back to IPv6.
  - `"resolve-domains-and-prefer-ipv6"`
    Resolve domain targets, prefer IPv6, and fall back to IPv4.
  - `"resolve-domains-and-use-only-ipv4"`
    Resolve domain targets and use only IPv4 answers. If DNS returns no IPv4 answer, the line is closed.
  - `"resolve-domains-and-use-only-ipv6"`
    Resolve domain targets and use only IPv6 answers. If DNS returns no IPv6 answer, the line is closed.
  - `"resolve-domains-with-core-settings"`
    Resolve domain targets using the DNS settings and result preference configured in `core.json` under `dns`.

  When local resolution is enabled, `VlessClient` creates an internal `DomainResolver` whose prepare hook applies the
  configured target before DNS resolution.
  Resolution is applied when the final VLESS target address is a domain. This includes both fixed JSON addresses and
  `"dest_context->address"`. Literal IP addresses are left unchanged. While DNS is pending, the internal resolver queues
  payloads before the VLESS request starts.

## Protocol Behavior

Request format:

```text
version:      00
uuid:         16 raw bytes
addons len:   00
command:      01 TCP or 02 UDP
destination:  port first, then address
```

Destination format:

```text
port:         2 bytes big-endian
address type: 01 IPv4, 02 domain, 03 IPv6
address body: IPv4 4 bytes, domain length + bytes, or IPv6 16 bytes
```

Response format:

```text
00 00
```

## First payload and transport establishment

`Init` prepares the destination and starts the next node without emitting a request.
The first eligible application payload may arrive before transport `Est`, during its
callback, or while Pause is recorded. It is sent immediately with the complete request
in one ordinary buffer, including one UDP frame header when applicable. Ordinary input
is reused in place when its headroom fits all headers. Otherwise a best-fit ordinary
buffer is allocated; any resident prefix and private-pipe body are copied in order.
Empty TCP input does not trigger a request. Empty VLESS UDP datagrams are dropped locally.

Transport `Est` reaches the live application once, independently of protocol data and
Pause. If the request remains unsent, its first-payload deadline starts at that Est.
`settings.first-payload-timeout-ms` defaults to **400**, accepts integers from **0** to
**4,294,967,295**, and rejects other types and ranges. Zero disables deliberate waiting.
Paused time counts. Expiry sends one header-only request when transport output is
writable; while paused it retains only a due obligation until Resume. An eligible
payload arriving first cancels that timer and sends the combined output. Duplicate
Est/Resume cannot repeat the request or reset its deadline. Finish cancels the timer.
One ordinary output does not promise one syscall, TCP packet, or TLS record.

Direct TCP and per-datagram upstream forwarding do not wait for Est or Resume and do
not keep application output queues. VLESS downstream parsing validates version 0 and consumes exactly the response header and its addons, at most 257 bytes. Nonempty addons are skipped with a warning. Outbound input never waits for this response.

UDP application lines remain borrowed UDP-facing lines. The client creates one dependent,
owned TCP carrier on the application's worker and maps Est, Pause/Resume and Finish to
that association. The request carries the fixed target; each frame has a two-byte big-endian length.
The UDP decoder finishes every complete datagram in an admitted input even when an earlier
delivery causes Pause. Nested input joins the guarded parser FIFO behind older input;
only incomplete framing/order state remains. Finish, malformed input or receiver refusal
stops delivery and closes the affected association. Only this node's owned carrier is
destroyed here; the application owner drains it during shutdown.

## Notes And Caveats

- `TlsClient` is required for ordinary VLESS deployments, but it is not inserted automatically.
- This implementation sends empty request addons. It accepts a non-empty response addons section (logging a warning and skipping the addons bytes) for interoperability, but it does not act on any addon.
- Unsupported VLESS features include flow, XTLS Vision, mux, reverse, XUDP, and transport-specific wrappers.
- UDP payloads with length `0` or greater than `65535` are dropped locally.
- Malformed downstream response headers or UDP frames close the affected line safely.
- `required_padding_left` is `280`, covering the largest initial request plus a UDP length prefix.

## Splice and retention

The first request plus payload is ordinary; the request itself is at most 278 bytes.
Later opaque TCP preserves its original ordinary or splice representation. UDP sends
prepend two bytes within the advertised 280-byte padding budget. Header parsing and exact body
movement preserve boundaries and use complete ordinary fallback when padding or pipe
capacity requires it. Receive extraction preserves full onward padding.

| Retained parser input | Inclusive logical limit |
| --- | --- |
| TCP body input retained only for parser reentry ordering | 2,097,152 bytes (2 MiB) |
| TCP response assembly, including active head and cached metadata | 2,097,409 bytes (2 MiB plus 257 bytes) |
| UDP wire assembly, including active head and cached headers | 2,162,689 bytes (2 MiB plus 65,537 bytes) |
| UDP body | 1 through 65,535 bytes |

Equality passes; overflow or parser queue refusal closes the association. There is no
retained decoded-output queue or 1,024-record limit on a synchronous batch. Fragment
counts do not consume output slots. These are logical protocol limits, independent
of buffer-pool size, RAM profile, and pipe capacity. Oversized local datagrams are
dropped; malformed received frames close the association. A received zero-length UDP frame is malformed.

Splice requires `misc.splice`, a supported build and support from every node in the
final chain, including internal helpers. `DomainResolver` supports splice. `TlsClient`
still blocks splice for its entire chain. Keep TLS in ordinary deployment configurations;
splice capability does not guarantee zero-copy or a measured speed increase.

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
| `required_padding_left` | `280` bytes |
