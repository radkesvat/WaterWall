<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/VlessClient.mdx, and both files must keep the same documentation version.
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

`VlessClient` forwards downstream `Est` when the downstream transport establishes. Upstream payload emitted by that `Est`
callback is queued until the VLESS request header is sent, then flushed immediately after the header without waiting for
the VLESS response header. Downstream body bytes are still held until the response header is parsed and validated.

## Notes And Caveats

- `TlsClient` is required for ordinary VLESS deployments, but it is not inserted automatically.
- This implementation sends empty request addons. It accepts a non-empty response addons section (logging a warning and skipping the addons bytes) for interoperability, but it does not act on any addon.
- Unsupported VLESS features include flow, XTLS Vision, mux, reverse, XUDP, and transport-specific wrappers.
- UDP payloads with length `0` or greater than `65535` are dropped locally.
- Malformed downstream response headers or UDP frames close the affected line safely.
- `required_padding_left` is `2`, enough for the VLESS UDP length prefix.
