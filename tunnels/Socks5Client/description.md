# Socks5Client Node

`Socks5Client` is a stream middle-tunnel that speaks the client side of the SOCKS5 protocol.

It reads its target settings from JSON, sends the SOCKS5 greeting and optional username/password authentication, then
submits a SOCKS5 command for the configured target destination. Upstream application payload is held until the proxy
accepts the request.

## Typical Placement

Typical chain:

`TcpListener <-> Socks5Client <-> TcpConnector`

Important:

- `Socks5Client` can use either fixed JSON target values or the incoming `line->dest_ctx`
- it resolves the final SOCKS target during `Init` and mirrors that result into `line->routing_context.dest_ctx`
- the actual TCP connection to the SOCKS proxy itself is still made by the next adapter, usually a `TcpConnector`
  with a constant proxy address/port

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
  Currently only `"tcp"` / `"connect"` is supported.

- `settings.user` and `settings.pass`
  Optional SOCKS5 username/password authentication. If one is present, the other must also be present.

- `settings.verbose`
  Enables extra tunnel logging.

## Behavior

- `Init` initializes per-line state and mirrors the configured target into the line destination context.
- the resolved SOCKS target is also kept in `Socks5Client` line state so the proxy transport connector can rewrite
  `line->dest_ctx` without changing the later SOCKS `CONNECT` request.
- if `address` and/or `port` use `dest_context`, the incoming line destination is used as the SOCKS target source
- `DownStreamEst` starts the SOCKS5 method negotiation.
- `DownStreamPayload` consumes method, auth, and command replies from the proxy.
- `UpStreamPayload` is buffered until the SOCKS5 command succeeds.
- only after a successful proxy reply does the tunnel emit `tunnelPrevDownStreamEst()` and release buffered payload
- on handshake failure it destroys local state first, then closes both directions

## Notes And Caveats

- this tunnel is stream-oriented and does not implement UDP ASSOCIATE data-plane behavior
- `protocol: "udp"` is therefore rejected conservatively
- `required_padding_left = 0`
