# Socks5Client Node

`Socks5Client` is a stream middle-tunnel that speaks the client side of the SOCKS5 protocol.

It reads its target settings from JSON, sends the SOCKS5 greeting and optional username/password authentication, then
submits a SOCKS5 command for the configured target destination. It supports TCP `CONNECT` and UDP `ASSOCIATE`.
Upstream application payload is held until the proxy accepts the request.

## Typical Placement

TCP proxy chain:

`TcpListener <-> Socks5Client <-> TcpConnector`

UDP-capable proxy chain:

`TcpUdpListener <-> Socks5Client <-> TcpUdpConnector`

Important:

- `Socks5Client` can use either fixed JSON target values or the incoming `line->dest_ctx`
- it prepares the final SOCKS target during `Init` and mirrors that result into `line->routing_context.dest_ctx`
- the actual connection to the SOCKS proxy itself is still made by the next adapter, usually a connector with a constant
  proxy address/port
- UDP mode creates a TCP control line for `UDP ASSOCIATE` and a UDP relay line for SOCKS UDP datagrams, so the next
  adapter should be `TcpUdpConnector` when UDP is used

## Configuration Example

```json
{
  "name": "socks-client",
  "type": "Socks5Client",
  "next": "proxy-connector",
  "settings": {
    "address": "dest_context->address",
    "port": "dest_context->port",
    "protocol": "tcp",
    "user": "alice",
    "pass": "secret",
    "domain-strategy": "do-not-resolve-domains",
    "verbose": false
  }
}
```

Accepted address keys:

- `address`
- `target-address`
- `target`

Accepted credential keys:

- `user` or `username`
- `pass` or `password`

## Domain Resolution Example

```json
{
  "name": "socks-client",
  "type": "Socks5Client",
  "next": "proxy-connector",
  "settings": {
    "address": "example.com",
    "port": 443,
    "protocol": "tcp",
    "domain-strategy": "resolve-domains-and-prefer-ipv4"
  }
}
```

With this setting, `Socks5Client` resolves `example.com` before sending the SOCKS5 command. If an IPv4 answer is
available, the SOCKS5 request encodes that IPv4 address instead of the domain name. If no IPv4 answer is available, it
falls back to IPv6.

## Required JSON Fields

- `settings.address`
  The target host or IP that should appear in the SOCKS5 request.
  It may be a literal host/IP or `"dest_context->address"`.

- `settings.port`
  The target port that should appear in the SOCKS5 request.
  It may be a number or `"dest_context->port"`.

## Optional JSON Fields

- `settings.protocol`
  Selects the SOCKS command and the protocol placed in `line->routing_context.dest_ctx`.

  Supported values:

  - `"tcp"` or `"connect"`
    Force the destination context protocol to TCP and send a SOCKS5 `CONNECT` request.
  - `"udp"` or `"udp-associate"`
    Force the destination context protocol to UDP, negotiate SOCKS5 `UDP ASSOCIATE`, and send payloads as SOCKS UDP
    datagrams.
  - `"dest_context->protocol"` or `"line->dest_ctx->protocol"`
    Preserve the protocol already present in the incoming destination context. An exact TCP flag behaves like `"tcp"`;
    an exact UDP flag behaves like `"udp"`.

  If `dest_context->protocol` is selected but the incoming destination context protocol is missing, ambiguous, or not
  TCP/UDP, `Socks5Client` logs a warning and falls back to TCP.

  Default: `"tcp"`

- `settings.user` and `settings.pass`
  Optional SOCKS5 username/password authentication. If one is present, the other must also be present.

- `settings.verbose`
  Enables extra tunnel logging.

- `settings.domain-strategy`
  Controls whether `Socks5Client` resolves domain targets before encoding the SOCKS5 command or UDP packet destination.

  Default: `"do-not-resolve-domains"`.

  Supported values:

  - `"do-not-resolve-domains"`
    Keep domain targets as domains in the SOCKS5 request. This preserves the previous behavior and lets the SOCKS5
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

  When local resolution is enabled, `Socks5Client` creates an internal `DomainResolver` after its target setup step.
  Resolution is applied when the final SOCKS target address is a domain. This includes both fixed JSON addresses and
  `"dest_context->address"`. Literal IP addresses are left unchanged. While DNS is pending, the internal resolver queues
  payloads before the SOCKS5 handshake starts.

## Behavior

- an internal setup node mirrors the configured target into the line destination context before the protocol core starts.
- the resolved SOCKS target is kept in `Socks5Client` line state so the proxy transport connector can rewrite
  `line->dest_ctx` without changing the later SOCKS request.
- if `domain-strategy` enables resolution and the target is a domain, DNS resolution happens before the SOCKS5 greeting
  is sent by the internal `DomainResolver`.
- if `address` and/or `port` use `dest_context`, the incoming line destination is used as the SOCKS target source
- if `protocol` uses `dest_context->protocol`, the incoming destination protocol is read before any configured
  address/port rewrite
- `DownStreamEst` starts the SOCKS5 method negotiation.
- `DownStreamPayload` consumes method, auth, and command replies from the proxy.
- `UpStreamPayload` is buffered until the SOCKS5 command succeeds.
- only after a successful proxy reply does the tunnel emit `tunnelPrevDownStreamEst()` and release buffered payload
- on handshake failure it destroys local state first, then closes both directions
- in UDP mode, upstream payload is wrapped in a SOCKS5 UDP request header and sent through the UDP relay line
- in UDP mode, downstream relay datagrams have the SOCKS5 UDP header stripped before payload is forwarded back

## Notes And Caveats

- SOCKS5 UDP fragmentation is not reassembled; datagrams with `FRAG != 0` are ignored conservatively.
- UDP mode expects the proxy listener topology to make the UDP associate reply address reachable from the client.
- `required_padding_left` is set for the worst-case SOCKS5 UDP header so UDP mode can prepend datagram headers without
  breaking Waterwall buffer-padding assumptions.
