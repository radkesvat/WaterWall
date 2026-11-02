# MUX first frame probe

Splits the carrier's bytes into separate small reads so that a child's first DATA frame reaches `MuxServer` in pieces, and checks that `VlessServer` still accepts the UUID.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `application`: `TcpListener` → `vless-client`
- `vless-client`: `VlessClient` → `mux-client`
- `mux-client`: `MuxClient` → `carrier-out`
- `carrier-out`: `TcpConnector` (the probe's splitting relay, which connects to `carrier-in`)
- `carrier-in`: `TcpListener` → `mux-server`
- `mux-server`: `MuxServer` → `vless-server`
- `vless-server`: `VlessServer` → `destination`
- `destination`: `TcpConnector` (the probe's service)

CTest selections and overrides:

- `waterwall.mux_first_frame_probe` — default runner settings.

Success: every round's request and response arrive unchanged. Without whole first frames `VlessServer` logs `rejected segmented UUID authentication` and closes the line.
