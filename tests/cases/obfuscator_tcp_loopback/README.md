# Obfuscator tcp loopback


Exercises the obfuscator tcp loopback scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `obfuscator-client`
- `obfuscator-client`: `ObfuscatorClient` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `obfuscator-server`
- `obfuscator-server`: `ObfuscatorServer` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

CTest `waterwall.obfuscator_tcp_loopback` runs this configuration through the [namespace harness](../../run_in_network_namespace.sh) and [roundtrip runner](../../run_waterwall_case.sh). Both peers must verify their plaintext and complete within the supplied deadline.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).

TLS-like framing is enabled on both peers. Client upstream output reaches Server upstream input across the TCP connection; server replies use Server downstream encoding and Client downstream decoding.
