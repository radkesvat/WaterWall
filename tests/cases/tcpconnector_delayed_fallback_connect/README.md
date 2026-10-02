# tcpconnector_delayed_fallback_connect

## Execution and checks

Queued application bytes survive delayed fallback connector establishment. Real loopback listener/echo and fixed connect retries; checks the complete queued payload, preserving the original premature-close RuntimeError.

Topology: listener: TcpListener → tls-server; tls-server: TlsServer → protected; protected: TcpConnector; fallback: TcpConnector.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.tcpconnector_delayed_fallback_connect`.
