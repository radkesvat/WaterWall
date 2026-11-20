# HTTP/2 upload close over TLS

The real chain is `TcpListener` → `HttpClient` → `TlsClient` → `TcpConnector`
→ the probe's TLS peer. The existing runner supplies the certificate/key from the
TLS round-trip fixture and a private namespace. ALPN must negotiate `h2`.

Reuses the plain HTTP/2 upload probe's 1 KiB-window, 128 KiB accepted upload, late
response, and response END_STREAM case. After application Finish and a PING
barrier, fresh window credit lets HttpClient send the remaining request bytes and
HTTP/2 END_STREAM before finishing TlsClient. TcpConnector uses ordinary full
close on this carrier. The peer sends its final window credit and then only reads,
checking the complete HTTP/2 body, its stream end and EOF.

A second chain enables `stay-alive` and sets the upload deadline to 1000 ms.
The TLS peer observes both sides finish the HTTP/2 stream, then obtains a
PING acknowledgment on the same connection after the upload deadline.
A new application establishes an independent TLS connection. Sending GOAWAY
on the original connection produces EOF.

CTest: `waterwall.http2_upload_close_tls_probe` (30-second runner deadline).
