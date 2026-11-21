# RtmpServer

`RtmpServer` accepts a live publication from [RtmpClient](../RtmpClient/description.md) and connects it to the next node.
Each RTMP connection carries one ordered, full-duplex application byte stream. Peers must implement
WaterWall's `ww.data` messages. Ordinary video publishing and playback use a different payload format.

The node selects TCP from the destination transport offer during `Init`.
It closes lines whose offers do not include TCP.

## Typical placement

```text
RTMP   TcpListener → RtmpServer → TcpConnector
RTMPS  TcpListener → TlsServer → RtmpServer → TcpConnector
```

The listener opens the carrier port. For RTMPS, `TlsServer` presents the certificate and decrypts the
connection before RTMP sees it. The final connector selects the destination service.
See [TlsServer](../TlsServer/description.md) for certificate and private key settings.

## Minimal practical example

This node fragment accepts the default application and stream names. Define `service` as a
`TcpConnector` that can reach the backend, for example at `127.0.0.1:8080`.

```json
{
  "name": "rtmp",
  "type": "RtmpServer",
  "next": "service",
  "settings": {}
}
```

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `app` | `waterwall` | Accepted RTMP application name, 1–127 bytes. Must match the client. |
| `stream` | `tunnel` | Accepted live stream name, 1–255 bytes. Must match the client. |
| `payload-block-size` | `16384` | Maximum application bytes per outgoing message, an integer from 1 to 65,536. Each peer chooses its own value. |
| `handshake-timeout-ms` | `10000` | Time allowed for RTMP setup through publication acceptance, in milliseconds from 1 to 2,147,483,647. |
| `send-stall-timeout-ms` | `30000` | Time that queued application output may wait without progress toward the carrier, in milliseconds from 1 to 2,147,483,647. Idle sessions with empty queues can stay open. |

The application and stream names select the publication. Protect a public listener separately if it should
accept only authorized clients. With ordinary verified RTMPS, the server certificate proves the server's
identity to the client.

## When the backend opens

After validating the application and stream names, `RtmpServer` initializes the next node.
Once that call returns with the session open, the server accepts the publication and can
exchange application bytes. A destination connection may still be pending at that point.

For example, place `VlessServer` directly after `RtmpServer`. VLESS reads the destination
from the first application bytes and then opens its outbound connection.

## Usage and troubleshooting

- **TCP connects but setup fails.** Check that the carrier reaches the correct plain or TLS listener and that both RTMP nodes use the same `app` and `stream`. If RTMP succeeds but the application connection fails, check the destination address and port from the server.
- **An application expects a reply after EOF.** Application-side EOF ends the session in both directions and cancels unsent bytes. A direct TCP carrier can reset during close, truncating bytes sent just before EOF. Applications that need a final reply must read it while the stream is open.
- **Application reads have different sizes.** Delivery preserves byte order. Read sizes on either side can differ from RTMP message sizes.

For a custom build, the CMake option is `INCLUDE_RTMP_SERVER`. RTMP framing uses ordinary buffers and blocks
TCP splice on this chain.

For paired client and server configurations, see [Direct tunnel over RTMP and RTMPS](https://radkesvat.github.io/WaterWall-Docs/docs/examples/tunnels/direct-rtmp)
and [SOCKS5 proxy over RTMPS](https://radkesvat.github.io/WaterWall-Docs/docs/examples/proxies/rtmp).
