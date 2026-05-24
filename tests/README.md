# Waterwall Tests

The test tree is split by scope:

- `unittests/`
  Small library-level tests that build standalone executables and do not launch `Waterwall`.
- `cases/`
  Integration cases that run the real `Waterwall` binary through the shell harness.

See [unittests/README.md](/root/WaterWall/tests/unittests/README.md) for the unit-test list and workflow.

## Integration Tests

These tests run the real `Waterwall` binary with synthetic chains built from:

- `TesterClient`
- the tunnel or tunnel-pair under test
- optional `Disturber`
- `TesterServer`

## Which runner should I use?

There are two valid ways to run these integration tests:

- `ctest`
  This is the normal, recommended entry point.
  Use it when you want to run registered tests by name, by pattern, or all at once.
- `tests/run_waterwall_case.sh`
  This is the low-level single-case runner.
  `ctest` calls this script underneath for each registered case.

Practical rule:

- most users should start with `ctest`
- use `run_waterwall_case.sh` directly when debugging one case or when you want to control the timeout and paths manually

## Current layout

- `unittests/`
  Unit-test sources and CMake registration.
- `cases/<name>/config.json`
  One Waterwall config file for a test case.
- `cases/<name>/workers.txt`
  Optional worker-count override for a case.
  If omitted, the runner uses its default worker count.
- `run_waterwall_case.sh`
  The low-level single-case runner.
  It creates a temporary `core.json`, launches `Waterwall`, watches the tester log, and fails on crash or timeout.
  After the tester success marker, it terminates Waterwall and still treats unexpected shutdown statuses as failures.
  The generated `core.json` uses `4` workers by default, unless the case directory provides `workers.txt`.
  The generated `core.json` uses the `client` RAM profile so stream cases are not bottlenecked by the minimal 4 KB
  large-buffer size.
- `CMakeLists.txt`
  Registers integration cases with CTest and delegates unit-test registration to `unittests/CMakeLists.txt`.

## Current cases

- `disturber_passthrough`
  Verifies that `Disturber` with default zero-probability settings behaves like a transparent middle tunnel.
- `obfuscator_roundtrip`
  Verifies that `ObfuscatorClient` and `ObfuscatorServer` preserve payload and finish ordering when paired directly.
- `obfuscator_tls_record_roundtrip`
  Verifies the same obfuscation pair while also exercising TLS-like record wrapping and stripping.
- `encryption_roundtrip`
  Verifies the default `EncryptionClient` and `EncryptionServer` framing pair across the full tester payload sequence.
- `encryption_small_frame_roundtrip`
  Verifies the encryption pair with `max-frame-size=4096`, so the framing logic is exercised even when the harness uses
  larger stream buffers.
- `tls_roundtrip`
  Verifies `TlsClient` and `TlsServer` chained directly with a self-signed test certificate, peer verification disabled
  on the client, SNI checked by the server, and streaming responses enabled so TLS traffic flows in both directions.
- `connection_fisher_roundtrip`
  Verifies that `ConnectionFisherClient` and `ConnectionFisherServer` complete their `5`-byte probe handshake and
  preserve the tester roundtrip across a real TCP loopback transport.
- `udp_over_tcp_roundtrip`
  Verifies that `UdpOverTcpClient` and `UdpOverTcpServer` preserve end-to-end byte stream integrity through their
  length-prefixed framing.
- `tcp_over_udp_roundtrip`
  Verifies that `TcpOverUdpClient` and `TcpOverUdpServer` preserve stream integrity through their KCP datagram path.
- `tcp_over_udp_fec_roundtrip`
  Verifies the same TCP-over-UDP pair with Reed-Solomon FEC enabled on both peers.
- `tcp_over_udp_disturber_roundtrip`
  Verifies that the TCP-over-UDP KCP stream survives packet loss, duplication, simple reordering, and jitter injected in
  both directions by `Disturber` between the client and server peers.
- `tcp_over_udp_fec_disturber_roundtrip`
  Verifies the same bidirectionally disturbed TCP-over-UDP path with Reed-Solomon FEC enabled on both peers.
- `packets_stream_bridge_roundtrip`
  Verifies that `PacketsToStream` and `StreamToPackets` preserve packet boundaries and payload integrity across their
  worker-packet-line to stream-line bridge.
- `udp_listener_packet_bridge_roundtrip`
  Verifies that `PacketsToStream -> UdpConnector -> UdpListener -> StreamToPackets` preserves packet integrity across
  a real UDP loopback transport while multiple workers create independent UDP peers against one shared listener socket.
- `udp_connector_packet_balance_mode_roundtrip`
  Verifies that `UdpConnector` accepts `balance-mode: "packet"` with multiple weighted `lvh.me` domain targets,
  resolves those targets through DNS, and preserves packet integrity while balancing packets across several UDP loopback
  listener ports.
- `ping_new_ip_icmp_roundtrip`
  Verifies `PingClient` and `PingServer` through a paired `Bridge`, including outer IPv4/ICMP wrapping, ICMP payload
  XOR, roundup padding, and PingServer's downstream decapsulation direction.
- `ping_reuse_ipv4_addresses_roundtrip`
  Verifies the bridged `wrap-in-icmp-header-and-reuse-ipv4-addresses` path, including reuse of the original IPv4 header
  and restoration of the tester packet's original IPv4 protocol.
- `ping_only_icmp_roundtrip`
  Verifies the bridged `wrap-in-only-icmp-header` path using raw packet-mode bytes rather than synthetic IPv4 packets.
- `ping_protocol_swap_roundtrip`
  Verifies the bridged `change-only-ipv4-protocol-number` path over the full packet IPv4 corpus because this strategy
  does not add bytes to packets.
- `ipmanipulator_tcp_udp_swap_roundtrip`
  Verifies that `IpManipulator` can rewrite IPv4 TCP protocol numbers to UDP and restore the response path.
- `ipmanipulator_udp_tcp_swap_roundtrip`
  Verifies the opposite `IpManipulator` protocol-number mapping, UDP to TCP and back on the response path.
- `ipmanipulator_tcp_udp_tcp_transport_roundtrip`
  Verifies two chained `IpManipulator` nodes can turn a synthetic TCP IPv4 packet into protocol `17` and restore it to
  a valid TCP packet before `TesterServer` sees it.
- `ipmanipulator_tcp_udp_tcp_transport_bridge_roundtrip`
  Verifies the same TCP -> protocol `17` -> TCP restoration when a `Bridge` feeds the manipulated packet downstream
  directly into the second `IpManipulator`, with `TesterServer` placed at the head of that paired chain.
- `halfduplex_roundtrip`
  Verifies that `HalfDuplexClient` and `HalfDuplexServer` split and reconstruct one logical line correctly.
- `http1_bidirectional_roundtrip`
  Verifies that `HttpClient(http1)` and `HttpServer(http1, full-duplex=true)` can stream request and response bodies at
  the same time when chained directly.
- `http1_bidirectional_tcp_loopback`
  Verifies the same HTTP/1.1 bidirectional body-streaming behavior across a real TCP loopback transport.
- `http1_split_roundtrip`
  Verifies that `HttpClient(http1-mode=split)` opens separate upload/download HTTP/1.1 requests, that
  `HttpServer(http1-mode=split)` pairs them by query/header metadata, and that the merged logical stream preserves the
  tester payload sequence across all workers.
- `http1_split_tcp_loopback`
  Verifies the split HTTP/1.1 transport across real TCP loopback sockets, including a custom upload method, separate
  upload/download paths, a header-carried pair ID, query-carried direction, cookie-carried token, and cache-bypass
  query parameter generation.
- `http1_split_path_cookie_roundtrip`
  Verifies alternate split metadata placement using path-carried IDs, cookie-carried direction markers, a header token,
  path-template cache values, and the `http1-split=true` compatibility alias.
- `http2_bidirectional_roundtrip`
  Verifies that direct HTTP/2 request and response DATA can overlap correctly through `HttpClient` and `HttpServer`.
- `http2_bidirectional_tcp_loopback`
  Verifies the same direct HTTP/2 bidirectional behavior across a real TCP loopback transport.
- `http_upgrade_h2c_bidirectional_roundtrip`
  Verifies default `h2c` upgrade plus bidirectional HTTP/2 DATA after the client opens a fresh post-upgrade tunnel
  stream.
- `http_upgrade_h2c_bidirectional_tcp_loopback`
  Verifies the same default `h2c` upgrade behavior across a real TCP loopback transport.
- `http2_request_validation_rejects_mismatch`
  Negative case: verifies that `HttpServer` rejects a direct HTTP/2 request whose method, path, and authority do not
  match its configured expectations.
- `http_websocket_bidirectional_roundtrip`
  Verifies HTTP/1.1 WebSocket handshake plus bidirectional framed payload transport when the pair is chained directly.
- `http_websocket_bidirectional_tcp_loopback`
  Verifies the same WebSocket transport across a real TCP loopback transport, including clean shutdown after the tester
  success marker.
- `http_upgrade_custom_bidirectional_roundtrip`
  Verifies a custom HTTP/1.1 upgrade token plus raw post-upgrade byte forwarding when the pair is chained directly.
- `http_upgrade_custom_bidirectional_tcp_loopback`
  Verifies the same custom-upgrade raw bidirectional transport across a real TCP loopback transport.
- `mux_counter_roundtrip`
  Verifies basic `MuxClient` and `MuxServer` framing in counter mode.
- `mux_timer_roundtrip`
  Verifies the same MUX pair in timer mode.
- `mux_fixed_connections_count_roundtrip`
  Verifies the same MUX pair in fixed connection count mode with two parent mux connections per worker while
  `ConnectionFisherClient` creates multiple child lines per worker.
- `reverse_tcp_bridge_roundtrip`
  Verifies `ReverseClient` and `ReverseServer` across a real TCP loopback transport while a paired `Bridge` links
  `TesterClient` to the reverse-server local side and `TesterServer` to the reverse-client local side.
- `wireguard_udpstateless_packet_roundtrip`
  Verifies two `WireGuardDevice` nodes across real UDP loopback sockets, using packet-mode testers with IPv4 packet
  payloads so AllowedIPs routing and transport encryption are both exercised end to end.

## Case selection notes

The current tester sends very large stream chunks up to `2 MB`, so not every tunnel is a valid fit for this harness.
Now that `TesterClient` and `TesterServer` split oversized logical chunks into `LargeBuffer`-sized payload buffers,
several framed tunnels are testable directly even when the logical end-to-end chunk is much larger than one physical
buffer.

The default `h2c` upgrade tests deliberately avoid carrying tunnel payload on stream `1`.
`nghttp2_session_upgrade2()` models stream `1` as the original HTTP/1.1 upgrade request, so Waterwall cancels that
stream and uses one fresh post-upgrade HTTP/2 stream for the bidirectional tunnel body.

## Adding a new tunnel test

1. Create `tests/cases/<name>/config.json`.
2. Add `tests/cases/<name>/workers.txt` only if the case needs a non-default worker count.
3. Use `TesterClient` as the chain head and `TesterServer` as the chain end.
4. Insert the tunnel pair you want to validate between them.
5. Add the case to [tests/CMakeLists.txt](/root/WaterWall/tests/CMakeLists.txt).

Example shape:

```json
{
  "name": "encryption-roundtrip",
  "nodes": [
    { "name": "tester-client", "type": "TesterClient", "next": "enc-client" },
    { "name": "enc-client", "type": "EncryptionClient", "next": "disturber" },
    { "name": "disturber", "type": "Disturber", "next": "enc-server" },
    { "name": "enc-server", "type": "EncryptionServer", "next": "tester-server" },
    { "name": "tester-server", "type": "TesterServer" }
  ]
}
```

For tunnels that are meant to prove real bidirectional overlap, the test harness also supports:

- `TesterClient.settings.allow-early-response=true`
- `TesterServer.settings.streaming-response=true`

Those options let response bytes arrive before the client has finished sending the full request sequence, which is
important for validating full-duplex transports such as the HTTP cases above.

## Running locally

```sh
cmake --preset linux-gcc-x64
cmake --build --preset linux-gcc-x64 --target check_waterwall_tests
```

Important:

- run commands from the repo root
- `ctest --preset linux-gcc` always reads the `build/linux-gcc-x64` tree, so if your IDE or CMake menu is building a
  different preset or build directory you may be testing a different binary than the one your menu just ran
- the Linux CTest presets use `Release`, matching the default Linux build preset
- direct `ctest` runs do not build missing executables.
  Build `waterwall_unit_tests`, `Waterwall`, or one of the `check_waterwall_*` targets first depending on the scope you
  want to run.

Run only unit tests:

```sh
cmake --build --preset linux-gcc-x64 --target check_waterwall_unit_tests
```

Run only integration tests:

```sh
cmake --build --preset linux-gcc-x64 --target check_waterwall_integration_tests
```

## What `run_waterwall_case.sh` does

When you run the helper script directly, it:

1. copies the selected case directory into a temporary run directory
2. writes a temporary `core.json`
3. launches the real `Waterwall` binary
4. waits for the built-in tester success log line
5. sends `SIGTERM` after success and checks that Waterwall exits cleanly
6. fails if `Waterwall` crashes, exits early, exits with an unexpected status after success, or times out
7. prints logs on failure to help debugging

So `run_waterwall_case.sh` is not a second testing system.
It is the small runner that powers each integration test invocation.

Success and failure are decided inside Waterwall:

- `TesterClient` / `TesterServer` detect mismatches and terminate the program on failure
- `TesterClient` logs the success marker on a passing run, and the helper accepts any worker count in that message
- `run_waterwall_case.sh` only watches for that success marker so it knows when the test is finished and can stop the
  still-running Waterwall process

## Listing available cases

Show every registered integration test:

```sh
ctest --preset linux-gcc -L integration -N
```

That prints names like:

- `waterwall.disturber_passthrough`
- `waterwall.obfuscator_roundtrip`
- `waterwall.encryption_roundtrip`

## Running one case

Recommended way with `ctest`:

```sh
ctest --preset linux-gcc --output-on-failure -R '^waterwall\.disturber_passthrough$'
```

Equivalent low-level way with the helper script:

```sh
tests/run_waterwall_case.sh \
  build/linux-gcc-x64/Release/Waterwall \
  tests/cases/disturber_passthrough \
  60
```

## Running two specific cases

Run only `disturber_passthrough` and `obfuscator_roundtrip`:

```sh
ctest --preset linux-gcc --output-on-failure -R '^waterwall\.(disturber_passthrough|obfuscator_roundtrip)$'
```

Another example for two encryption cases:

```sh
ctest --preset linux-gcc --output-on-failure -R '^waterwall\.(encryption_roundtrip|encryption_small_frame_roundtrip)$'
```

`run_waterwall_case.sh` runs only one case at a time.
If you want two or more cases in one command, use `ctest`.

## Running a group by pattern

Run every encryption-related case:

```sh
ctest --preset linux-gcc --output-on-failure -R '^waterwall\.encryption_'
```

Run every MUX case:

```sh
ctest --preset linux-gcc --output-on-failure -R '^waterwall\.mux_'
```

## When to use the helper script directly

Use `run_waterwall_case.sh` directly when:

- you want to debug one case in isolation
- you want to change the timeout for one run
- you want to point at a specific `Waterwall` binary manually
- you are experimenting with a case before registering it in `tests/CMakeLists.txt`

Example:

```sh
tests/run_waterwall_case.sh \
  build/linux-gcc-x64/Release/Waterwall \
  tests/cases/disturber_passthrough \
  60
```

## Quick workflow

Typical loop for editing one case:

```sh
cmake --preset linux-gcc-x64
cmake --build --preset linux-gcc-x64 --target Waterwall
ctest --preset linux-gcc --output-on-failure -R '^waterwall\.disturber_passthrough$'
```

Typical loop for debugging one case manually:

```sh
cmake --preset linux-gcc-x64
cmake --build --preset linux-gcc-x64 --target Waterwall
tests/run_waterwall_case.sh \
  build/linux-gcc-x64/Release/Waterwall \
  tests/cases/disturber_passthrough \
  60
```
