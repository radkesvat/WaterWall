# WaterWall RTMP transport

`RtmpClient` and `RtmpServer` carry an ordered, full-duplex byte stream between WaterWall peers. Each connection negotiates one live RTMP stream with object encoding 3. Application bytes travel in `ww.data` AMF3 ByteArray messages and emerge in the same order. The receiving application may see different read boundaries.

| Transport | Client chain | Server chain |
| --- | --- | --- |
| RTMP | `TcpListener → RtmpClient → TcpConnector` | `TcpListener → RtmpServer → TcpConnector` |
| RTMPS | `TcpListener → RtmpClient → TlsClient → TcpConnector` | `TcpListener → TlsServer → RtmpServer → TcpConnector` |
| UDP datagrams | `UdpListener → UdpOverTcpClient → RtmpClient → TcpConnector` | `TcpListener → RtmpServer → UdpOverTcpServer → UdpConnector` |

After a valid publication request, `RtmpServer` initializes the application branch and queues publish success once initialization returns with the session open. The branch can receive a request header before its destination connects. For a proxy, place `VlessClient` directly before `RtmpClient` and `VlessServer` directly after `RtmpServer`.

Configure matching application and stream names on the [client](../../RtmpClient/description.md) and [server](../../RtmpServer/description.md). For RTMPS, change the client’s `tc-url` scheme to `rtmps` and add the TLS nodes shown above. On `TlsServer`, set `cert-file` and `key-file` to the server certificate and private key. On `TlsClient`, set `sni` to the certificate’s hostname and keep `verify` enabled. Point the client’s `TcpConnector` at the RTMPS listener.

For example, set the client’s URL to `rtmps://rtmp.example.com:1935/waterwall`. Set the client `rtmp` node’s `next` to `carrier-tls` and the server `carrier` node’s `next` to `listener-tls`. Add these respective nodes to the client and server configurations.

```json
{
  "name": "carrier-tls",
  "type": "TlsClient",
  "settings": {"sni": "rtmp.example.com", "verify": true},
  "next": "carrier"
}
```

```json
{
  "name": "listener-tls",
  "type": "TlsServer",
  "settings": {"cert-file": "server.crt", "key-file": "server.key", "sni": "rtmp.example.com"},
  "next": "rtmp"
}
```

## Limits and closure

| Limit | Value |
| --- | ---: |
| Maximum inbound application block | 64 KiB |
| Maximum RTMP message body | 65,552 bytes |
| Read pressure high and low watermarks | 512 KiB and 256 KiB |
| Shared queued logical bytes per direction | 1 MiB |
| Shared retained allocation charge per direction | 2 MiB |
| Shared queued entries per direction | 1,024 |
| Separate active control-output allowance | 8 KiB of wire bytes |
| Peer bandwidth window | 256 KiB advertised, 64 KiB to less than 2 GiB accepted |
| Credit reserved for control traffic | 8 KiB |

The direction budgets cover plaintext and encoded output together, and carrier input and decoded output together. The parser separately bounds RTMP reassembly to three chunk streams. A protocol error, a limit refusal, an expired deadline, or loss of the carrier ends the stream. A new transport connection starts a new session.

An orderly RTMP close or carrier `Finish` delivers already-decoded bytes to the live application before closing it, including when EOF arrives in the same read as the final data. An application-side `Finish` cancels any unsent application bytes and ends the stream in both directions. Applications that need a final reply must receive it while the stream is open.

On direct TCP chains, RTMP pauses application reads while it retains unsent bytes, allowing ordinary source EOF to follow handoff to the next node on the carrier side. Each carrier node handles its accepted output during `Finish`. In an RTMPS chain, TLS handles pending ciphertext and the TCP adapter hands accepted writes to WIO for ordinary socket close. A transport error or peer reset can interrupt final delivery.

The peer must implement WaterWall’s `ww.data` profile. Use external WaterWall nodes for TLS, datagram framing, and multiplexing.

## Build and test

Enable `INCLUDE_RTMP_CLIENT` and `INCLUDE_RTMP_SERVER` to build the two node types. The production and unit trees use separate presets. The production tests below run in a private Linux network namespace and check plain RTMP, RTMPS, negotiation timeout, and composition with VLESS and UDP-over-TCP.

The [dependency notes](patches/README.md) record the engine revision and describe the local adaptations.

```sh
cmake --preset linux -DINCLUDE_RTMP_CLIENT=ON -DINCLUDE_RTMP_SERVER=ON
cmake --build --preset linux -j8
ctest --preset linux --output-on-failure --no-tests=error -R '^waterwall\.rtmps?_'

cmake --preset linux-unit-tests -DINCLUDE_RTMP_CLIENT=ON -DINCLUDE_RTMP_SERVER=ON
cmake --build --preset linux-unit-debug --target rtmp_protocol_test rtmp_pair_test rtmp_engine_test rtmp_lifecycle_test -j8
ctest --preset linux-unit-debug --output-on-failure --no-tests=error -R '^waterwall\.rtmp_'
cmake --build --preset linux-unit-release --target rtmp_protocol_test rtmp_pair_test rtmp_engine_test rtmp_lifecycle_test -j8
ctest --preset linux-unit-release --output-on-failure --no-tests=error -R '^waterwall\.rtmp_'
```
