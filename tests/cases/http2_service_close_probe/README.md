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

CTest selections and overrides:

- `waterwall.http2_service_close_probe` — default runner settings.

Success: every round receives the exact response and then EOF within 10 seconds.
