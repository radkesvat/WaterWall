# Examples

This folder contains runnable and copyable configuration patterns for common WaterWall deployment topologies:

- `vless_tls_server.json`: Basic VLESS server with generic TLS fallback. `TlsServer` terminates TLS directly; clearly non-TLS traffic falls back before TLS commitment.
- `vless_tls_sni_camouflage_server.json`: SNI-aware camouflage topology using `SniffRouter` in front of `TlsServer`. Visible ClientHello with the expected SNI routes to `TlsServer` -> `VlessServer`, while mismatched SNI, no-SNI, and plaintext traffic fall back to a real nginx HTTPS listener untouched.

**Note:** For a deeper understanding of each node/pair and more comprehensive examples with expected behaviors, refer to the integration tests and the developer guides.
