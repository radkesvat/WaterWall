<!--
Documentation version: 107
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/HeaderServer.mdx, and both files must keep the same documentation version.
-->

# HeaderServer

`HeaderServer` is the server-side reader for small connection metadata headers.
It can do three different jobs:

- consume the WaterWall 2-byte port header from `HeaderClient` and write it into `dest_context->port`
- consume HAProxy PROXY protocol v1 or v2 and write the advertised client IPv4 and port into `src_context`
- set one constant destination port during upstream `Init`

It is a normal layer-4 stream tunnel. It does not create sockets, packet lines,
or `line_t` objects.

## Typical Placement

WaterWall destination-port metadata:

```text
client side: TcpListener -> HeaderClient -> TcpConnector
server side: TcpListener -> HeaderServer -> TcpConnector
```

PROXY protocol source metadata from a trusted proxy:

```text
trusted PROXY sender -> TcpListener -> HeaderServer -> TcpConnector
```

Constant destination port:

```text
TcpListener -> HeaderServer -> TcpConnector
```

Use PROXY mode only behind a trusted sender. A raw internet client can forge a
PROXY header unless a proxy or a private transport boundary prevents that.

## Practical Examples

### Restore the original listener port from HeaderClient

This is the classic WaterWall pair. The first instance listens on multiple
public ports but sends everything to one relay port. The relay restores the
original accepted port before `TcpConnector` chooses the local backend.

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

The matching client-side `HeaderClient` should use:

```json
{
  "name": "header-client",
  "type": "HeaderClient",
  "settings": {
    "data": "src_context->port"
  },
  "next": "relay-connector"
}
```

### Read source IP and port from PROXY protocol

Use this when the previous real peer sends HAProxy PROXY protocol and the next
WaterWall nodes should see the original client as `line->routing_context.src_ctx`.

```json
{
  "name": "proxy-source-reader",
  "type": "HeaderServer",
  "settings": {
    "override": "proxy-protocol->source-fields"
  },
  "next": "router-or-connector"
}
```

The sender may be HAProxy, nginx, Envoy, or `HeaderClient` configured with
`"proxy-protocol"`, `"proxy-protocol-v1"`, or `"proxy-protocol-v2"`.

Example WaterWall sender:

```json
{
  "name": "proxy-header",
  "type": "HeaderClient",
  "settings": {
    "data": "proxy-protocol",
    "frontend-ipv4": "203.0.113.10"
  },
  "next": "relay-connector"
}
```

In this mode, `HeaderServer` accepts only IPv4 TCP PROXY headers. It consumes the
header, writes the source IP and source port into `src_ctx`, then initializes the
next upstream node and forwards any payload that followed the header.

### Force one backend port

Use a numeric override when every line should use the same destination port and
no header should be consumed.

```json
{
  "name": "force-https",
  "type": "HeaderServer",
  "settings": {
    "override": 443
  },
  "next": "connector"
}
```

Do not place a header-writing `HeaderClient` before numeric mode unless you
intentionally want that header to remain in the application payload.

## Required JSON Fields

Top-level fields:

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | User-chosen node name. Must be unique inside the config file. |
| `type` | string | Must be exactly `"HeaderServer"`. |
| `settings` | object | Required. Must contain `override`. |
| `next` | string | Required. The next layer-4 stream node receives the routed line. |

Required `settings` fields:

| Field | Type | Description |
| --- | --- | --- |
| `override` | number or string | Selects which field is overridden and which header, if any, is consumed. |

`HeaderServer` must also have a previous node in the chain. It is not a chain
head or chain end.

## settings.override

Accepted values:

| Value | Meaning |
| --- | --- |
| `"dest_context->port"` | Read the 2-byte WaterWall upstream header and set `dest_ctx.port`. |
| `"line->dest_ctx->port"` | Compatibility alias for `"dest_context->port"`. |
| `"proxy-protocol->source-fields"` | Read PROXY protocol v1 or v2, then set `src_ctx.ip` and `src_ctx.port`. |
| `1` through `65535` | Set this constant destination port during upstream `Init`. |

Startup fails if `override` is missing, is not one of the accepted strings, or
is a number outside `1` through `65535`.

## WaterWall Port Header Mode

When `override` is `"dest_context->port"` or `"line->dest_ctx->port"`,
`HeaderServer` waits for the first 2 upstream bytes. Those bytes are decoded as
a big-endian port and written to:

```text
line->routing_context.dest_ctx.port
```

Upstream `Init` is intentionally delayed until the header is decoded. Payload
bytes are staged in a `buffer_stream_t`, so the 2-byte header may arrive split
across payload callbacks.

Decoded ports below `10` are rejected to preserve the tunnel's existing
conservative close behavior.

## PROXY Protocol Source-Fields Mode

When `override` is `"proxy-protocol->source-fields"`, the first upstream bytes
must be a valid HAProxy PROXY protocol v1 or v2 header. If the header is missing,
malformed, not IPv4, or does not carry source fields, `HeaderServer` logs an
error and closes the line.

Accepted headers:

| Header | Accepted form |
| --- | --- |
| PROXY v1 | `PROXY TCP4 <source-ip> <dest-ip> <source-port> <dest-port>\r\n` |
| PROXY v2 | version 2, `PROXY` command, `TCP4` family/transport |

Rejected headers include:

- PROXY v1 `UNKNOWN`
- PROXY v1 `TCP6`
- PROXY v2 `LOCAL`
- PROXY v2 `UNSPEC`, `TCP6`, `UDP4`, `UDP6`, or any unsupported family
- malformed or oversized headers

Only these fields are applied:

```text
line->routing_context.src_ctx.ip_address = PROXY source IPv4
line->routing_context.src_ctx.port       = PROXY source port
line->routing_context.src_ctx.protocol   = TCP
```

Destination fields, TLVs, and every other PROXY field are consumed but ignored.
IPv6 is not supported in this mode. `peer_source_port` is not rewritten.

PROXY v1 is capped at `108` bytes. PROXY v2 consumes the full v2 record length,
including any TLVs, but requires the fixed TCP4 address block to be present.

## Constant Override Mode

When `override` is a number, `HeaderServer` does not read or strip any payload
header.

During upstream `Init`, it sets:

```text
line->routing_context.dest_ctx.port = configured port
```

Then it immediately forwards upstream `Init` to `next`. All upstream payload is
forwarded unchanged.

## Direction Behavior

| Direction | Delayed header modes |
| --- | --- |
| upstream `Init` | Initialize local state, but delay `next` init until the configured header is decoded. |
| upstream payload before header | Buffer until the full configured header is available. |
| upstream payload after header | Forward to `next`. |
| upstream pause/resume before header | Ignored; there is no initialized next side yet. |
| upstream pause/resume after header | Forward to `next`. |
| downstream `Est` / pause / resume before header | Ignored. |
| downstream payload before header | Recycled, then the previous side is closed. |
| downstream callbacks after header | Forward to the previous node. |

In constant mode, the line starts established during upstream `Init`, so normal
upstream and downstream callbacks are forwarded directionally.

`UpStreamEst` and `DownStreamInit` are disabled callbacks for this node.

## Finish Behavior

On upstream `Finish`, `HeaderServer` destroys local line state. It forwards the
finish to `next` only if the line had already completed header routing and
initialized the next side.

On downstream `Finish`, it destroys local line state and forwards the finish to
the previous node.

On protocol error, it destroys local state, closes `next` if `next` had already
been initialized, and closes the previous side.

The tunnel does not call `lineDestroy()` because it does not create the line.

## Limits and Padding

| Value | Size |
| --- | --- |
| WaterWall port header | `2 bytes` |
| minimum accepted WaterWall header port | `10` |
| PROXY protocol v1 header | up to `108 bytes` |
| PROXY protocol v2 base header | `16 bytes` |
| PROXY protocol v2 required TCP4 address block | `12 bytes` |
| `required_padding_left` | `0 bytes` |

The server only consumes headers. It does not prepend bytes and therefore does
not require left padding.

## Notes and Caveats

- Use WaterWall port-header mode with `HeaderClient.data = "src_context->port"`.
- Use PROXY source-fields mode with a trusted PROXY sender.
- PROXY source-fields mode is IPv4-only.
- PROXY source-fields mode updates only `src_ctx`; it does not rewrite `dest_ctx`.
- While waiting for a header, `HeaderServer` has not initialized the next tunnel yet.
- It should not be used as packet-line shared state.
