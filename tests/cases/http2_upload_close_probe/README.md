# HTTP/2 upload close probe

Checks that `HttpClient` preserves accepted request bytes after the application
closes, while its independent carrier finishes HTTP/2 output. The existing probe
runner starts the real runtime inside a private network namespace.

Raw-peer chains:

- `normal-application` (`TcpListener`, port 26800) → `normal-http`
  (`HttpClient`, default drain timeout) → `normal-carrier` (`TcpConnector`).
- `timed-application` (port 26802) → `timed-http` (1000 ms drain timeout) →
  `timed-carrier`.
- `upgrade-application` (port 26806) → `upgrade-client` (h2c upgrade) →
  `upgrade-carrier`.
- `websocket-application` (port 26807) → `websocket-client` (WebSocket over
  HTTP/2) → `websocket-carrier`.

All connect to the probe's raw HTTP/2 peer on port 26801. A 1 KiB receive window
blocks a 128 KiB request. The verbose DATA admission log proves all 128 KiB reached
HttpClient before the application closes. The TcpListener close marker followed
by a PING round trip establishes that the application Finish has completed.

Cases verify:

- Later WINDOW_UPDATE grants deliver the exact accepted body, END_STREAM, and TCP
  EOF. Response DATA arriving after application Finish is discarded safely; the
  response's own END_STREAM does not cancel the remaining upload.
- Application Finish before the h2c handshake retains pending payload. Only after
  Finish does the peer send its 101 response and HTTP/2 settings. The resulting
  tunnel stream must deliver the exact body, END_STREAM, and EOF. The existing
  upgrade stream cancellation is allowed separately from tunnel cancellation.
- Application Finish before the WebSocket extended-CONNECT response retains
  pending payload. After a successful response, independently decoded masked
  binary frames must reproduce the exact body, followed by a WebSocket close,
  HTTP/2 END_STREAM, and EOF.
- Silent peers trigger the autonomous 1000 ms deadline. PING and one-byte window
  grants every 100 ms cause replies and real upload progress but cannot extend
  that original deadline. Both cases require EOF between 0.6 and 2 seconds after
  application close, with the exact incomplete request prefix and no END_STREAM.
- RST_STREAM(CANCEL) promptly closes the carrier and any still-open application,
  both before application Finish and while a retained upload is blocked.
- Carrier loss closes an open application and safely cancels an upload drain.

A separate production chain uses `pair-application` (port 26803) → `HttpClient`
→ `TcpConnector` → `TcpListener` (port 26804) → `HttpServer` → `TcpConnector`
→ the probe's backend (port 26805). Closing the source after a 4 MiB write must
still deliver every byte and then EOF to that backend. This also checks runtime
survival after the cancellation cases.

The probe checks transport delivery, not an application-level acknowledgement.
Native HTTP client fixtures separately exercise exact state, timer, and buffer
cleanup. Socket operations are bounded by 10 seconds and log barriers by 5
seconds. The case runner's overall deadline is 60 seconds.

CTest: `waterwall.http2_upload_close_probe`.
