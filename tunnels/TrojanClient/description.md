<!--
Documentation version: 159
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
    "domain-strategy": "do-not-resolve-domains",
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
    "domain-strategy": "resolve-domains-and-prefer-ipv4"
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

- `settings.domain-strategy`
  Controls whether `TrojanClient` resolves domain targets before encoding the Trojan request or UDP packet destination.

  Default: `"do-not-resolve-domains"`.

  Supported values:

  - `"do-not-resolve-domains"`
    Keep domain targets as domains in the Trojan request. This preserves the previous behavior and lets the Trojan
    server side resolve the target domain.
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

  When local resolution is enabled, `TrojanClient` creates an internal `DomainResolver` whose prepare hook applies the
  configured target before DNS resolution.
  Resolution is applied when the final Trojan target address is a domain. This includes both fixed JSON addresses and
  `"dest_context->address"`. Literal IP addresses are left unchanged. While DNS is pending, the internal resolver queues
  payloads before the Trojan request starts.

## First payload and transport establishment

`Init` prepares the destination and starts the next node without emitting a request.
The first eligible application payload may arrive before transport `Est`, during its
callback, or while Pause is recorded. It is sent immediately with the complete request
in one ordinary buffer, including one UDP frame header when applicable. The source's
resident prefix and private-pipe body are fully materialized into that first output.
Empty TCP input does not trigger a request. Empty Trojan UDP datagrams are valid.

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
not keep application output queues. Trojan has no success response; downstream TCP is opaque from Init.

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
prepend within the advertised 263-byte padding budget. Header parsing and exact body
movement preserve boundaries and use complete ordinary fallback when padding or pipe
capacity requires it. Receive extraction preserves full onward padding.

| Retained parser input | Inclusive logical limit |
| --- | --- |
| UDP wire input, including active head and cached header | 2,105,607 bytes (2 MiB plus one maximum frame) |
| UDP body | 8,192 bytes; empty bodies are valid |

Equality passes; overflow or parser queue refusal closes the association. There is no
retained decoded-output queue or 1,024-record limit on a synchronous batch. Fragment
counts do not consume output slots. These are logical protocol limits, independent
of buffer-pool size, RAM profile, and pipe capacity. Oversized local datagrams are
dropped; malformed received frames close the association. Received source addresses are validated without changing the application destination.

Splice requires `misc.splice`, a supported build and support from every node in the
final chain, including internal helpers. `DomainResolver` supports splice. `TlsClient`
still blocks splice for its entire chain. Keep TLS in ordinary deployment configurations;
splice capability does not guarantee zero-copy or a measured speed increase.

## Notes And Caveats

- `TlsClient` is required for ordinary Trojan compatibility and probe resistance, but it is not inserted automatically.
- `TrojanClient` does not implement server fallback behavior; fallback is a server-side feature.
- outbound UDP payloads larger than 8192 bytes are dropped to match the current `TrojanServer` packet limit without
  killing the whole local association.
- inbound Trojan UDP frames larger than 8192 bytes are treated as invalid protocol input.
- `required_padding_left` is set for the worst-case Trojan UDP header so UDP mode can prepend packet headers without
  breaking Waterwall buffer-padding assumptions.

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
| `required_padding_left` | `263` bytes |
