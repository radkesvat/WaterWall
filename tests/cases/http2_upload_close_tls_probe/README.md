# HTTP/2 upload close over TLS

The real chain is `TcpListener` → `HttpClient` → `TlsClient` → `TcpConnector`
→ the probe's TLS peer. The existing runner supplies the certificate/key from the
TLS round-trip fixture and a private namespace. ALPN must negotiate `h2`.

Reuses the plain HTTP/2 upload probe's 1 KiB-window, 128 KiB accepted upload, late
response, and response END_STREAM case. After application Finish and a PING
barrier, fresh window credit must deliver every request byte, HTTP/2 END_STREAM,
and EOF. This exercises close-linger propagation through TlsClient. The existing
TLS direct-close policy does not send `close_notify`; all HTTP/2 bytes and its
explicit stream end are still required before EOF.

CTest: `waterwall.http2_upload_close_tls_probe` (30-second runner deadline).
