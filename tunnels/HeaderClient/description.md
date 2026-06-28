<!--
Documentation version: 110
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/HeaderClient.mdx, and both files must keep the same documentation version.
-->

# HeaderClient

`HeaderClient` prepends a one-time header to the first upstream payload on each normal layer-4 line.

It is most often used for one of two jobs:

- passing WaterWall routing metadata to a paired `HeaderServer`
- adding a HAProxy PROXY protocol header before traffic reaches a receiver that understands PROXY protocol

`HeaderClient` does not open sockets and does not create lines. It only mutates the first upstream payload, then becomes transparent for the rest of the line.

## What It Does

- Requires `settings.data` to choose the one-time header format.
- Initializes local line state on upstream `Init`.
- Immediately forwards upstream `Init` to `next`.
- Prepends the configured header only on the first upstream payload.
- Supports the old 2-byte WaterWall port header.
- Supports IPv4-only HAProxy PROXY protocol v1 and v2 headers with a configured frontend IPv4 address.
- Forwards every later upstream payload unchanged.
- Forwards downstream payload, `Est`, `Pause`, and `Resume` unchanged.
- Destroys local line state before forwarding either directional `Finish`.

## Typical Placement

Internal WaterWall port header:

```text
TcpListener -> HeaderClient -> ... -> HeaderServer -> TcpConnector
```

PROXY protocol header for a PROXY-aware remote receiver:

```text
sender side:   TcpListener -> HeaderClient -> TcpConnector
receiver side: HeaderServer/HAProxy/nginx/backend
```

In PROXY protocol mode, the next real peer must expect HAProxy PROXY protocol.
That can be `HeaderServer` with `settings.override =
"proxy-protocol->source-fields"` or another PROXY-aware backend. PROXY mode also
requires `settings.frontend-ipv4`, which should be the frontend IPv4 address
clients connect to, not the backend address.

## Practical Examples

### Preserve the accepted listener port through a relay

This is the classic `HeaderClient` plus `HeaderServer` use case. A client-side WaterWall instance listens on several public ports, but sends all traffic to one relay port on another WaterWall instance. The relay side restores the original accepted port into `dest_context->port` before connecting to the local service.

Client side:

```json
[
  {
    "name": "public-listener",
    "type": "TcpListener",
    "settings": {
      "address": "0.0.0.0",
      "port": [80, 443, 8443]
    },
    "next": "header-client"
  },
  {
    "name": "header-client",
    "type": "HeaderClient",
    "settings": {
      "data": "src_context->port"
    },
    "next": "relay-connector"
  },
  {
    "name": "relay-connector",
    "type": "TcpConnector",
    "settings": {
      "address": "198.51.100.20",
      "port": 9000
    }
  }
]
```

Relay side:

```json
[
  {
    "name": "relay-listener",
    "type": "TcpListener",
    "settings": {
      "address": "0.0.0.0",
      "port": 9000
    },
    "next": "header-server"
  },
  {
    "name": "header-server",
    "type": "HeaderServer",
    "settings": {
      "override": "dest_context->port"
    },
    "next": "local-service"
  },
  {
    "name": "local-service",
    "type": "TcpConnector",
    "settings": {
      "address": "127.0.0.1",
      "port": "dest_context->port"
    }
  }
]
```

With this layout, a connection accepted by the client side on public port `443` is relayed to `198.51.100.20:9000`, then the relay side connects to `127.0.0.1:443`.

### Force all relayed traffic to one backend port

Use a numeric `settings.data` when the relay side expects the 2-byte WaterWall header, but the value should be fixed instead of copied from the line context.

```json
{
  "name": "header-client",
  "type": "HeaderClient",
  "settings": {
    "data": 8443
  },
  "next": "relay-connector"
}
```

On the paired side, configure `HeaderServer` to read that header and write it into `dest_context->port`, then let `TcpConnector` use `"dest_context->port"`. Every line through this client will select backend port `8443`.

### Send PROXY protocol v2 to a local backend

Use `"proxy-protocol"` when the next real peer is HAProxy, nginx, Envoy, or another service that expects a PROXY protocol line before the original client payload.

```json
[
  {
    "name": "public-listener",
    "type": "TcpListener",
    "settings": {
      "address": "0.0.0.0",
      "port": 443
    },
    "next": "proxy-header"
  },
  {
    "name": "proxy-header",
    "type": "HeaderClient",
    "settings": {
      "data": "proxy-protocol",
      "frontend-ipv4": "203.0.113.10"
    },
    "next": "backend"
  },
  {
    "name": "backend",
    "type": "TcpConnector",
    "settings": {
      "address": "192.0.2.50",
      "port": 443
    }
  }
]
```

`"proxy-protocol"` is an alias for `"proxy-protocol-v2"`. PROXY protocol v2 is compact, binary, and the preferred default when the backend supports it. Set `frontend-ipv4` to the IPv4 address the client uses to reach this WaterWall frontend. Do not set it to `0.0.0.0` or to the backend's address.

### Send PROXY protocol v1 for legacy receivers

Some older receivers only accept the text PROXY protocol format. Use `"proxy-protocol-v1"` for that case:

```json
{
  "name": "proxy-header",
  "type": "HeaderClient",
  "settings": {
    "data": "proxy-protocol-v1",
    "frontend-ipv4": "203.0.113.10"
  },
  "next": "backend"
}
```

The receiver must be configured to expect PROXY protocol v1. For WaterWall
receivers, use `HeaderServer` with `settings.override =
"proxy-protocol->source-fields"`.

## Required JSON Fields

Top-level fields:

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | User-chosen node name. Must be unique inside the config file. |
| `type` | string | Must be exactly `"HeaderClient"`. |
| `settings` | object | Required. Must contain `data`. |
| `next` | string | Required. The next layer-4 stream node receives the header-prefixed stream. |

Required `settings` fields:

| Field | Type | Description |
| --- | --- | --- |
| `data` | number or string | Header format and data to encode into the first upstream payload. |

Conditionally required `settings` fields:

| Field | Type | Description |
| --- | --- | --- |
| `frontend-ipv4` | string | Required when `data` is `"proxy-protocol"`, `"proxy-protocol-v1"`, or `"proxy-protocol-v2"`. This must be the frontend IPv4 address clients connect to. |

`HeaderClient` must also have a previous node in the chain. It is not a chain head or chain end.

## `settings.data`

Accepted values:

| Value | Meaning |
| --- | --- |
| `1` through `65535` | Encode this constant port as the WaterWall 2-byte port header. |
| `"src_context->port"` | Encode `line->routing_context.src_ctx.port` as the WaterWall 2-byte port header. |
| `"line->src_ctx->port"` | Compatibility alias for `"src_context->port"`. |
| `"proxy-protocol"` | Emit a PROXY protocol v2 header. |
| `"proxy-protocol-v1"` | Emit a PROXY protocol v1 header. |
| `"proxy-protocol-v2"` | Emit a PROXY protocol v2 header. |

Startup fails if `data` is missing, is not one of the accepted string values, or is a numeric value outside `1` through `65535`.

## Wire Behavior

For numeric and source-context port modes, the first upstream payload is rewritten from:

```text
payload
```

to:

```text
2-byte port header | payload
```

The port header is a big-endian 16-bit value. It is sent only once per line. Later upstream payloads are forwarded exactly as received.

For PROXY protocol modes, `HeaderClient` emits an IPv4 TCP PROXY header. The source IP comes from `line->routing_context.src_ctx`. The destination IP comes from `settings.frontend-ipv4`; `dest_ctx` is not used for the PROXY destination because `TcpConnector` may rewrite `dest_ctx` to the backend it dials before the first payload is sent.

The selected ports are:

- source port: `routing_context.peer_source_port` when present, otherwise `src_ctx.port`
- destination port: `routing_context.local_listener_port` when present, otherwise `src_ctx.port`

If the source address is not IPv4 when the first upstream payload arrives, v1 emits `PROXY UNKNOWN` and v2 emits a LOCAL/UNSPEC header. IPv6 PROXY headers and PROXY protocol TLVs are not emitted.

If the first upstream payload is empty, the tunnel still sends the configured header on that first payload callback.

## Routing Context Notes

`HeaderClient` only serializes information already available on the line. It does not resolve domains and does not invent missing address fields.

For the old WaterWall port-header mode, this usually means:

- `TcpListener` puts the accepted local listener port into `src_ctx.port`
- `HeaderClient` can copy that value into the 2-byte header
- `HeaderServer` can restore it into `dest_ctx.port` on the other side

For PROXY protocol mode, the source address context must be convertible to an IPv4 socket address. The destination address in the PROXY header is the configured `frontend-ipv4`, not `dest_ctx`. This is intentional: in common chains such as `TcpListener -> HeaderClient -> TcpConnector`, `dest_ctx` usually describes the backend selected by `TcpConnector`, not the frontend address the client reached.

## Pairing With HeaderServer

Use `HeaderClient` with `HeaderServer` in one of the matching modes.

For the WaterWall 2-byte port header:

```json
{
  "name": "header-server",
  "type": "HeaderServer",
  "settings": {
    "override": "dest_context->port"
  },
  "next": "connector"
}
```

For PROXY protocol source-field restoration:

```json
{
  "name": "header-server",
  "type": "HeaderServer",
  "settings": {
    "override": "proxy-protocol->source-fields"
  },
  "next": "connector"
}
```

Pair that with `HeaderClient.data` set to `"proxy-protocol"`,
`"proxy-protocol-v1"`, or `"proxy-protocol-v2"`. The server-side PROXY reader is
IPv4-only and applies only `src_ctx.ip` and `src_ctx.port`.

If `HeaderServer.settings.override` is a number, the server sets a constant destination port during upstream `Init` and does not consume a header. In that mode, a `HeaderClient` in front of it would leave the 2-byte header in the application payload.

## Direction Behavior

| Direction | Behavior |
| --- | --- |
| upstream `Init` | Initialize line state, then forward to `next`. |
| upstream first payload | Prepend the configured header, then forward to `next`. |
| later upstream payload | Forward unchanged to `next`. |
| upstream pause/resume | Forward to `next`. |
| downstream payload | Forward unchanged to the previous node. |
| downstream `Est` / pause / resume | Forward to the previous node. |

`UpStreamEst` and `DownStreamInit` are disabled callbacks for this node.

## Finish Behavior

On upstream `Finish`, `HeaderClient` destroys its local line state and forwards the finish to `next`.

On downstream `Finish`, it destroys local line state and forwards the finish to the previous node.

The tunnel does not call `lineDestroy()` because it does not create the line.

## Limits and Padding

| Value | Size |
| --- | --- |
| WaterWall port header | `2 bytes` |
| PROXY protocol v1 header | up to `108 bytes` |
| PROXY protocol v2 header | `16` or `28 bytes` |
| `required_padding_left` | `108 bytes` |

The node declares `required_padding_left = 108` because it prepends the largest supported header with `sbufShiftLeft()`.

## Notes and Caveats

- Use it only in layer-4 stream chains.
- It should not be used as packet-line shared state.
- The 2-byte port header is internal WaterWall tunnel metadata, not a public protocol.
- PROXY protocol modes are IPv4-only for now.
- PROXY protocol destination IP comes from `settings.frontend-ipv4`, not `dest_ctx`.
- If one listener accepts traffic on multiple frontend IPv4 addresses, one fixed `frontend-ipv4` may not describe every accepted connection correctly.
- The encoded value is taken when the first upstream payload arrives.
- It only mutates the first upstream payload; the response path is transparent.
