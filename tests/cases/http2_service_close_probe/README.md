# HTTP/2 service close probe

Closes the service side right after a large response and checks that the client still receives all of it.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `application`: `TcpListener` → `http-client`
- `http-client`: `HttpClient` (HTTP/2) → `carrier-out`
- `carrier-out`: `TcpConnector` (TCP to `carrier-in`)
- `carrier-in`: `TcpListener` → `http-server`
- `http-server`: `HttpServer` (HTTP/2) → `service`
- `service`: `TcpConnector` (the probe's service)

The probe's service reads a short request, writes a 16 MiB response and closes at once, so `HttpServer` receives `Finish` with response data still queued.

Two focused cases connect directly to `carrier-in` with a raw HTTP/2 client. A
1 KiB receive window leaves a 128 KiB response blocked after the service closes.
The service-close log followed by a PING round trip establishes that WaterWall
has processed the close before the client continues:

- The client sends more request DATA, then connection and stream WINDOW_UPDATE
  frames. The closed service must receive no further data, while the client gets
  the exact response, END_STREAM, and TCP EOF.
- The client disconnects while the response is blocked. The runtime must survive
  and complete the three subsequent 16 MiB response rounds. Native HTTP transport
  tests separately verify exact cleanup of the retained session and buffers.

An independent `timed-carrier-in` → `timed-http-server` → `timed-service` chain
uses `close-drain-timeout-ms: 1000` and the same service. Two further cases leave
the response blocked after the backend closes:

- The client sends no more frames. The autonomous timer must close the connection.
- The client sends PING and one-byte connection/stream WINDOW_UPDATE grants every
  100 ms. PING replies and small response chunks must arrive, but neither activity
  nor progress may extend the original deadline.

Both require EOF with the exact incomplete response prefix, between 0.6 and 2
seconds after observing the backend close and completing a PING barrier. The
normal transport idle timeout is much longer. The original large-response chain
omits the setting, so those rounds retain the default deadline.

CTest selections and overrides:

- `waterwall.http2_service_close_probe` — default runner settings.

Success: the late-upload case receives the exact response and END_STREAM before
EOF, and every large-response round receives the exact response and then EOF.
Socket operations have a 10-second timeout; waiting for the service-close marker
has a 5-second deadline. The existing runner provides the overall 60-second bound.
