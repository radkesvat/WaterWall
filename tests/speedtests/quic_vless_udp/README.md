# VLESS over raw QUIC over UDP

Exercises the exact application chains:

```text
SpeedTestClient -> VlessClient -> QuicClient -> UdpConnector
UdpListener -> QuicServer -> VlessServer -> SpeedTestServer
```

The frozen functional throughput workload has one worker, two concurrent normal
lines, verified bidirectional stream data, 65,536-byte DATA bodies, 250 ms warmup
and one 3,000 ms measured interval. It uses default `h3` ALPN and explicit
`datagram` carrier mode. The local certificate and replacement trust root are
copied from `../_shared`; no public service or DNS is involved. This is a raw
private application stream, not HTTP/3. These choices define this workload and
are not performance tuning advice.

`waterwall.quic_speedtest_vless_udp` runs serially under the namespace harness.
It requires exit 0, one complete successful aggregate client JSON summary, both
lines, positive sent/received byte counts, payload verification, and zero failed
streams, lost packets or validation errors. It prints upload/download Mbit/s as
the aggregate measured bytes times eight divided by three seconds. There is no
portable minimum throughput or performance comparison gate.

```bash
WATERWALL_TEST_KEEP_RUN_DIR=1 ctest --test-dir build/linux -C Release -V \
  -R '^waterwall\.quic_speedtest_vless_udp$'
```

The retained private directory contains generated settings, complete runtime
logs and `throughput.json`. Failure retains artifacts automatically; success
requires the environment override above. The ordinary speed runner can also use
this directory, but the Python integration driver additionally checks the
aggregate report and prints the calculated rates.
