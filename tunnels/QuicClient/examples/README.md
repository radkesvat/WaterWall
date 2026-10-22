# Raw QUIC carrier examples

Each `datagram/{client,server}` or `stream/{client,server}` directory contains a
complete independent `core.json` and `config.json`. Run the client and server
from separate directories. These configurations use loopback so they can be
tried on one machine; for separate hosts change the client's carrier address to
the server address and the server listener address to its desired interface.

```text
client: TcpListener:1080 -> QuicClient -> UdpConnector:4433
server: UdpListener:4433 -> QuicServer -> TcpConnector:9000
```

The `stream` pair instead uses `TcpConnector`/`TcpListener` and sets
`carrier-mode=stream` on both QUIC nodes. Its four-byte outer datagram length is
private framing over a byte stream. The `datagram` pair emits ordinary QUIC
datagrams with no outer envelope. Adapter selection and carrier mode are user
configuration; no automatic detection or downgrade occurs.

Create a local test certificate with an ASCII DNS name before starting either
pair. From this directory:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
  -subj '/CN=quic.example.test' -addext 'subjectAltName=DNS:quic.example.test' \
  -keyout server.key -out server.crt
cp server.crt datagram/client/server.crt
cp server.crt datagram/server/server.crt
cp server.key datagram/server/server.key
cp server.crt stream/client/server.crt
cp server.crt stream/server/server.crt
cp server.key stream/server/server.key
```

The client explicitly verifies `quic.example.test` using `server.crt` as its
replacement trust bundle. SNI does not resolve or change the carrier's
`127.0.0.1` destination. Use an appropriate certificate chain/private key and
trust source for your deployment; keep the private key on the server.

Start any ordinary TCP service at `127.0.0.1:9000`, then run Waterwall from the
selected server directory and selected client directory with an absolute path
to the built executable. Each uses its local `core.json`. Connect an ordinary
TCP client to `127.0.0.1:1080`; the QUIC nodes carry its byte stream to the
service. Do not run the datagram and stream examples simultaneously on the same
application ports. For a local HTTP service, one possible service/client pair is
`python3 -m http.server 9000 --bind 127.0.0.1` and
`curl http://127.0.0.1:1080/`. HTTP here is application data inside the private
stream; announcing `h3` does not turn the QUIC connection into HTTP/3.

For the exact verified throughput chains, see
[`tests/speedtests/quic_vless_udp`](../../../../tests/speedtests/quic_vless_udp):

```text
SpeedTestClient -> VlessClient -> QuicClient -> UdpConnector
UdpListener -> QuicServer -> VlessServer -> SpeedTestServer
```

Those deterministic tests run through the private namespace harness and print
upload/download Mbit/s. Each QUIC association belongs to one existing normal
line and one application stream. There is no pooling, 0-RTT, HTTP/3 peer
interoperability, cross-line migration, or delivery guarantee after local
Finish teardown.
