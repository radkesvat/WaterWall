# RtmpClient

`RtmpClient` carries one ordered, full-duplex byte stream per RTMP connection. It publishes a live stream to
[RtmpServer](../RtmpServer/description.md). Both peers carry application bytes in WaterWall's `ww.data` messages, so the
remote endpoint must understand that profile. A video ingest URL alone is insufficient.

The node selects TCP from the destination transport offer during `Init`.
It closes lines whose offers do not include TCP.

## Typical placement

```text
RTMP   TcpListener → RtmpClient → TcpConnector
RTMPS  TcpListener → RtmpClient → TlsClient → TcpConnector
```

Set the RTMP URL, TCP endpoint and TLS hostname independently.

| Setting | Example | What it controls |
| --- | --- | --- |
| `RtmpClient.settings.tc-url` | `rtmps://tunnel.example.com:443/waterwall` | Application URL announced in the RTMP handshake. |
| `TcpConnector.settings.address` and `port` | `198.51.100.20` and `443` | Actual network endpoint to dial. |
| `TlsClient.settings.sni` | `tunnel.example.com` | Hostname sent during TLS setup and checked against the peer certificate with `verify: true`. |

For RTMPS, insert the TLS nodes on both peers and select the `rtmps://` scheme. Plain RTMP sends the
application data and stream names in cleartext. See [TlsClient](../TlsClient/description.md) for certificate verification.

## Minimal practical example

This node fragment sends RTMP traffic to a `TlsClient` named `carrier-tls`. The peer uses the default
application name `waterwall` and stream name `tunnel`.

```json
{
  "name": "rtmp",
  "type": "RtmpClient",
  "next": "carrier-tls",
  "settings": {
    "tc-url": "rtmps://tunnel.example.com:443/waterwall"
  }
}
```

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `tc-url` | **Required** | `rtmp://` or `rtmps://` URL with a host and a nonempty application path, at most 255 bytes. |
| `app` | `waterwall` | RTMP application name, 1–127 bytes. Must match the server. |
| `stream` | `tunnel` | Name of the live stream to publish, 1–255 bytes. Must match the server. |
| `payload-block-size` | `16384` | Maximum application bytes per outgoing message, an integer from 1 to 65,536. Each peer chooses its own value. |
| `handshake-timeout-ms` | `10000` | Time allowed for session setup, including publication acceptance, in milliseconds from 1 to 2,147,483,647. |
| `send-stall-timeout-ms` | `30000` | Time that queued application output may wait without progress toward the carrier, in milliseconds from 1 to 2,147,483,647. Idle sessions with empty queues can stay open. |

The application and stream names identify the publication. Anyone who knows them can supply the same
values. Configure authentication separately when the deployment requires it.

## Usage and troubleshooting

- **Setup times out.** Check the connector's address and port, TLS placement and certificate name. A successful TCP connection still leaves RTMP setup to complete. Check that the peer speaks the WaterWall RTMP profile and uses the same `app` and `stream`.
- **The last bytes are missing.** Application-side EOF closes both directions and cancels unsent bytes. A direct TCP carrier can also reset during close and truncate bytes sent just before EOF. Read any required reply while the stream is open.
- **Application reads have different sizes.** The receiving application sees the bytes in order. It can receive one write across several reads, or several writes together.

For a custom build, the CMake option is `INCLUDE_RTMP_CLIENT`. RTMP framing uses ordinary buffers and blocks
TCP splice on this chain.

Use [Direct tunnel over RTMP and RTMPS](https://radkesvat.github.io/WaterWall-Docs/docs/examples/tunnels/direct-rtmp) to forward a fixed TCP service.
Use [SOCKS5 proxy over RTMPS](https://radkesvat.github.io/WaterWall-Docs/docs/examples/proxies/rtmp) when each connection chooses its destination.
