<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TrojanClient.mdx, and both files must keep the same documentation version.
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

  When local resolution is enabled, `TrojanClient` creates an internal `DomainResolver` after its target setup step.
  Resolution is applied when the final Trojan target address is a domain. This includes both fixed JSON addresses and
  `"dest_context->address"`. Literal IP addresses are left unchanged. While DNS is pending, the internal resolver queues
  payloads before the Trojan request starts.

## Behavior

- an internal setup node prepares the final Trojan target before the protocol core starts.
- if `domain-strategy` enables resolution and the target is a domain, DNS resolution happens before the Trojan request
  is sent by the internal `DomainResolver`.
- for TCP, `Init` forwards the same line to the next node.
- for UDP, `Init` creates an internal TCP carrier line and forwards that carrier to the next node.
- `DownStreamEst` on the transport sends the Trojan request header.
- `TrojanClient` does not wait for a Trojan response; the protocol has no success reply.
- upstream payload is buffered until the request header has been sent.
- TCP downstream payload is forwarded unchanged after the request header is sent.
- UDP downstream payload is parsed as Trojan UDP packets before being forwarded to the previous UDP-facing line.
- malformed or oversized Trojan UDP frames from the carrier close the affected line safely.
- oversized local UDP payloads are dropped without closing the UDP association.
- invalid targets and queue overflows close the affected line safely.

## Notes And Caveats

- `TlsClient` is required for ordinary Trojan compatibility and probe resistance, but it is not inserted automatically.
- `TrojanClient` does not implement server fallback behavior; fallback is a server-side feature.
- outbound UDP payloads larger than 8192 bytes are dropped to match the current `TrojanServer` packet limit without
  killing the whole local association.
- inbound Trojan UDP frames larger than 8192 bytes are treated as invalid protocol input.
- `required_padding_left` is set for the worst-case Trojan UDP header so UDP mode can prepend packet headers without
  breaking Waterwall buffer-padding assumptions.
