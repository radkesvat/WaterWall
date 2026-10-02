# sniffrouter_tls_sni_camouflage_probe

## Execution and checks

Shared SniffRouter/TlsServer SNI fixture: matching/unknown/absent SNI and plain HTTP routing to protected/cover peers, followed by final connection accounting. Local TLS credentials and bounded messages/diagnostics; joined peer errors surface. Namespace harness owns runtime.

Topology: tcp-listener: TcpListener → sniff-router; sniff-router: SniffRouter → cover-connector; protected-tls-server: TlsServer → protected-connector; protected-connector: TcpConnector; cover-connector: TcpConnector.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.sniffrouter_tls_sni_camouflage_probe`.

Contract exercised: Verifies SNI routing with real-TLS cover fallback using a loopback probe: expected SNI completes through the protected
  `TlsServer` branch, while mismatched SNI, absent SNI, and plaintext HTTP on the public TLS port are routed untouched to
  the default cover fixture (which completes TLS with the observed SNI or returns an nginx-like 400 Bad Request error).
