# SpeedTestClient unverified TCP smoke

Exercises `SpeedTestClient -> TcpConnector -> loopback TcpListener -> SpeedTestServer`
with one worker, two bidirectional connections, 32 KiB payloads, no warmup and
250 ms of transfer. Omitting `verify-payload` checks the default unverified, splice-aware receive path; headers and sequence accounting remain active.

Run `ctest --preset linux --output-on-failure -R '^waterwall\\.speed_client_tcp_smoke_unverified$'`.
This case belongs to the routine functional lane and uses the existing speed
runner inside a private network namespace. Success requires SpeedTestClient to
finish with exit status zero before the ten-second runner deadline. The configured
transfer is a correctness smoke check, not throughput evidence.

The corresponding `tests/speedtests/tcp_loopback_unverified` workload remains
unchanged in the explicit speed lane. Generated settings and logs live in a
private run directory, retained on failure.
