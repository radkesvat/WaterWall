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
- it resolves the final SOCKS target during `Init` and mirrors that result into `line->routing_context.dest_ctx`
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

## Behavior

- `Init` initializes per-line state and mirrors the configured target into the line destination context.
- the resolved SOCKS target is also kept in `Socks5Client` line state so the proxy transport connector can rewrite
  `line->dest_ctx` without changing the later SOCKS request.
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
