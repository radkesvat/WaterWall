# TCP speed test without payload verification

Exercises `SpeedTestClient -> TcpConnector -> loopback TcpListener -> SpeedTestServer`
with the default `verify-payload=false`, bidirectional TCP, 16 connections, and
32 KiB payloads. The existing `tcp_loopback` case explicitly enables verification.

Run `ctest --preset linux --output-on-failure -R '^waterwall\.speedtest_tcp_loopback_unverified$'`.
The serial speed lane runs this case inside the private loopback namespace.
Success requires normal test completion and both direction reports. Headers,
frame lengths and sequence accounting remain active; payload bytes are not verified.
Throughput is diagnostic, not a portable acceptance threshold.

## Local throughput comparison

On 2026-10-02, the saved pre-change executable and the new default completed an
ABBA comparison on the same Linux 5.15 loopback host. Each workload used four
workers, the server RAM profile, 64 download streams, 128 KiB payloads, 500 ms
warmup and 5 s measurement. Mux used four carriers per worker. Each value below
is the mean of two successful runs, using aggregate received bytes divided by
the configured measurement duration.

| Workload | Previous default | New default | Ratio |
| --- | ---: | ---: | ---: |
| Direct TCP | 26.25 Gbit/s | 105.35 Gbit/s | 4.01× |
| TCP/Mux/TCP | 18.28 Gbit/s | 40.58 Gbit/s | 2.22× |

Disposition: keep. Both workloads exceeded the predeclared 5% gain threshold.
This compares the combined change: removing deterministic generation/verification
and enabling splice-aware receiving. It does not isolate splice's contribution,
is not a network-link benchmark, and establishes no portable throughput promise.
All runs completed without reported framing/sequence errors; unchecked payload
bytes were not independently validated. Raw logs remain outside source history.
