# tlsserver_sni_fallback_probe

## Execution and checks

Shared SniffRouter/TlsServer SNI fixture: matching/unknown/absent SNI and plain HTTP routing to protected/cover peers, followed by final connection accounting. Local TLS credentials and bounded messages/diagnostics; joined peer errors surface. Namespace harness owns runtime.

Topology: tcp-listener: TcpListener → protected-tls-server; protected-tls-server: TlsServer → protected-connector; protected-connector: TcpConnector; cover-connector: TcpConnector.

The case requests 1 workers; the override is part of its scenario.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.tlsserver_sni_fallback_probe`.

Contract exercised: Verifies direct TlsServer SNI routing without SniffRouter: matching SNI reaches the protected backend; mismatched SNI, absent SNI, and plaintext reach the cover listener.
