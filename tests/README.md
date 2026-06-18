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
- the tunnel or tunnel-pair under test, with optional `Disturber` inbetween.
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
- `speedtests/<name>/config.json`
  One Waterwall config file for a SpeedTestClient/SpeedTestServer case.
- `run_waterwall_case.sh`
  The low-level single-case runner.
  It creates a temporary `core.json`, launches `Waterwall`, watches the tester log, and fails on crash or timeout.
  After the tester success marker, it terminates Waterwall and still treats unexpected shutdown statuses as failures.
  The generated `core.json` uses `4` workers by default, unless the case directory provides `workers.txt`.
  The generated `core.json` uses the `client` RAM profile so stream cases are not bottlenecked by the minimal 4 KB
  large-buffer size.
- `run_waterwall_speedtest.sh`
  The low-level speedtest runner. It uses the same temporary `core.json` pattern but treats Waterwall exit status `0` as
  success, because `SpeedTestClient` terminates the process when all streams complete.
  If `speedtests/_shared/` exists next to the selected speedtest directory, the runner copies those shared fixtures into
  the temporary run directory before copying the selected case.
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
- `bgp4_roundtrip`
  Verifies that `Bgp4Client` and `Bgp4Server` preserve bidirectional stream payloads through BGP-like frames, including
  the first upstream OPEN frame and subsequent non-OPEN frames.
- `tls_roundtrip`
  Verifies `TlsClient` and `TlsServer` chained directly with a self-signed test certificate, peer verification disabled
  on the client, SNI checked by the server, and streaming responses enabled so TLS traffic flows in both directions.
- `reality_google_roundtrip`
  Verifies `TesterClient -> RealityClient -> TcpConnector` and `TcpListener -> RealityServer -> TesterServer` across a
  real TCP loopback hop while the Reality visitor branch handshakes with `google.com:443`.
- `reality_visitor_plaintext_probe`
  Verifies that non-TLS first bytes reaching `RealityServer` are immediately treated as visitor traffic instead of being
  held in the Reality sniff buffer.
- `connection_fisher_roundtrip`
  Verifies that `ConnectionFisherClient` and `ConnectionFisherServer` complete their `5`-byte probe handshake and
  preserve the tester roundtrip across a real TCP loopback transport.
- `sniffrouter_non_http_tcp_loopback`
  Verifies that `SniffRouter` sends non-HTTP first payload bytes to its normal `next` branch across a real TCP loopback
  transport; a configured `google.com` route points at an invalid local connector so accidental route selection fails.
- `sniffrouter_http_domain_tcp_loopback`
  Verifies that `SniffRouter` parses an HTTP/1.1 Host header, matches a wildcard domain from a multi-domain route, and
  forwards to that route's target while the top-level fallback `next` points at an invalid connector. The route enables
  both HTTP and TLS detection to exercise the combined detection setting while matching HTTP.
- `socks5_noauth_tcp_loopback`
  Verifies `Socks5Client` without credentials against `Socks5Server(no-auth=true)` across a real TCP proxy hop. The
  SOCKS request target is configured as `localhost` and resolved by
  `domain-strategy=resolve-domains-and-use-only-ipv4` before `Socks5Server` reaches the separate tester TCP listener
  through a `TcpConnector` using `dest_context`, so the case covers method `0x00` negotiation, client-side target
  resolution, and CONNECT target forwarding.
- `socks5_noauth_udp_loopback`
  Verifies `Socks5Client(protocol=udp)` without credentials against `Socks5Server(no-auth=true, udp=true)`. The proxy
  endpoint is a shared `TcpUdpListener`/`TcpUdpConnector` port, so the client negotiates UDP ASSOCIATE over TCP and then
  sends tester payloads as SOCKS UDP datagrams to a separate UDP tester listener selected from the SOCKS target setting.
- `socks5_noauth_dest_protocol_tcp_loopback`
  Verifies `Socks5Client(protocol=dest_context->protocol)` preserves an incoming TCP destination protocol and performs
  a SOCKS5 `CONNECT` through shared `TcpUdpListener`/`TcpUdpConnector` proxy endpoints.
- `socks5_noauth_dest_protocol_udp_loopback`
  Verifies `Socks5Client(protocol=dest_context->protocol)` preserves an incoming UDP destination protocol and performs
  a SOCKS5 `UDP ASSOCIATE`, including UDP relay payload wrapping and unwrapping.
- `socks5_noauth_dest_protocol_fallback_tcp_loopback`
  Verifies `Socks5Client(protocol=dest_context->protocol)` falls back to TCP when the incoming destination context has
  no valid protocol flags.
- `trojan_password_tcp_loopback`
  Verifies `TrojanClient(password=...) -> TlsClient -> TcpConnector` against
  `TcpListener -> TlsServer -> TrojanServer` using the real `AuthenticationClient -> AuthenticationServer` user database
  path. The Trojan TCP `CONNECT` target is configured as `localhost` and resolved by
  `domain-strategy=resolve-domains-and-use-only-ipv4` before the server reaches the separate tester TCP listener through
  `dest_context`.
- `trojan_sha224_dest_protocol_tcp_loopback`
  Verifies `TrojanClient(sha224=..., protocol=dest_context->protocol)` sends the precomputed SHA-224 password digest,
  preserves an incoming TCP destination context, and completes a Trojan TCP `CONNECT` through TLS.
- `trojan_password_udp_loopback`
  Verifies `TrojanClient(protocol=udp)` authenticates with a raw password, sends Trojan `UDP ASSOCIATE` over the TLS/TCP
  carrier, wraps UDP datagrams as Trojan UDP packets, and reaches a separate UDP tester listener.
- `trojan_dest_protocol_udp_loopback`
  Verifies `TrojanClient(protocol=dest_context->protocol)` preserves an incoming UDP destination context and completes
  Trojan UDP packet wrapping/unwrapping through `TrojanServer`.
- `vless_uuid_tcp_loopback`
  Verifies `VlessClient(uuid=...)` sends a plain VLESS v0 TCP request to `VlessServer`, validates the `00 00` response
  header, preserves an incoming TCP destination context, and reaches a separate tester TCP listener through the local
  UUID allowlist mode.
- `vless_uuid_udp_loopback`
  Verifies `VlessClient(protocol=dest_context->protocol)` sends a plain VLESS v0 UDP request to `VlessServer`, validates
  the response header, wraps datagrams as `uint16_be length + payload`, and reaches a separate UDP tester listener
  through the local UUID allowlist mode.
- `vless_auth_tcp_loopback`
  Verifies `VlessServer(auth-client-node-name=...)` converts the wire UUID to the canonical UUID password string,
  authenticates through `AuthenticationClient -> AuthenticationServer`, inserts its internal `UserController`, and
  completes a VLESS TCP request.
- `vless_auth_udp_loopback`
  Verifies the same database-backed VLESS authentication path for UDP, including the internal TCP carrier and backend
  UDP line carrying the authenticated user marker into `UserController`.
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
- `packets_stream_bridge_hard_validation_roundtrip`
  Verifies that `PacketsToStream` and `StreamToPackets` accept valid IPv4/TCP packets when `packet-validation-level` is
  set to `hard` on both sides of the bridge.
- `packets_stream_bridge_hard_validation_udp_roundtrip`
  Verifies the same `hard` validation path for valid IPv4/UDP packets, including UDP checksum verification.
- `udp_listener_packet_bridge_roundtrip`
  Verifies that `PacketsToStream -> UdpConnector -> UdpListener -> StreamToPackets` preserves packet integrity across
  a real UDP loopback transport while multiple workers create independent UDP peers against one shared listener socket.
- `udp_connector_packet_balance_mode_roundtrip`
  Verifies that `UdpConnector` accepts `balance-mode: "packet"` with multiple weighted `lvh.me` domain targets,
  resolves those targets through DNS, and preserves packet integrity while balancing packets across several UDP loopback
  listener ports.
- `udp_connector_listener_packet_loss_multiworker`
  Verifies a real UDP loopback hop across four workers using `PacketSender -> UdpConnector` on the sender side and
  `UdpListener -> PacketReceiver` on the receiver side, with the packet-analysis report requiring zero loss.
- `udp_listener_connector_packet_loss_multiworker`
  Verifies a two-hop UDP loopback path across four workers where the middle chain is `UdpListener -> UdpConnector`,
  exercising listener-created UDP lines that immediately feed another UDP connector, with zero packet loss required.
- `udp_listener_multiport_socket_packet_loss_multiworker`
  Verifies `UdpListener` with the socket multiport backend across four workers while `UdpConnector` sends to an integer
  destination port inside the listener's port range, with zero packet loss required.
- `udp_connector_listener_connection_multiworker_roundtrip`
  Verifies a stream-mode `TesterClient -> UdpConnector` and `UdpListener -> TesterServer` loopback across four workers
  using the full normal TesterClient/TesterServer payload corpus split into UDP-sized payloads by the tester nodes.
- `udp_listener_connector_connection_multiworker_roundtrip`
  Verifies the same stream-mode full-payload corpus across a two-hop UDP path where the middle chain is
  `UdpListener -> UdpConnector`.
- `udp_listener_multiport_socket_connection_multiworker_roundtrip`
  Verifies the stream-mode full-payload corpus through `UdpListener` with the socket multiport backend and an
  integer connector destination port inside the listener's port range.
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
- `reverse_custom_secret_tcp_bridge_roundtrip`
  Verifies the same reverse TCP bridge path when `ReverseClient` and `ReverseServer` use matching
  `reverse-secret-length` and `reverse-secret` settings.
- `wireguard_udpstateless_packet_roundtrip`
  Verifies two `WireGuardDevice` nodes across real UDP loopback sockets, using packet-mode testers with IPv4 packet
  payloads so AllowedIPs routing and transport encryption are both exercised end to end.

## Current speedtests

- `direct_pair`
  Runs `SpeedTestClient -> SpeedTestServer` with no tunnel between them as the in-process baseline.
- `tcp_loopback`
  Runs `SpeedTestClient -> TcpConnector` and `TcpListener -> SpeedTestServer` across one loopback TCP hop.
- `tcp_over_udp_direct_pair`
  Runs an unpaced `SpeedTestClient -> TcpOverUdpClient -> TcpOverUdpServer -> SpeedTestServer` path with FEC disabled.
- `tcp_over_udp_udp_sandwich`
  Runs `SpeedTestClient -> TcpOverUdpClient -> UdpConnector` and
  `UdpListener -> TcpOverUdpServer -> SpeedTestServer`, paced at `100 Mbits/sec` to avoid UDP adapter drop/backpressure
  noise and leaving FEC disabled.
- `obfuscator_direct_pair`
  Runs `SpeedTestClient -> ObfuscatorClient -> ObfuscatorServer -> SpeedTestServer`.
- `obfuscator_tcp_sandwich`
  Runs one loopback TCP hop into a middle `ObfuscatorClient -> ObfuscatorServer` pair, then one loopback TCP hop out to
  `SpeedTestServer`.
- `tls_direct_pair`
  Runs `SpeedTestClient -> TlsClient -> TlsServer -> SpeedTestServer` using the shared self-signed test certificate.
- `tls_tcp_sandwich`
  Runs a paced TLS pair across one loopback TCP hop between `TlsClient` and `TlsServer`.
- `encryption_direct_pair`
  Runs `SpeedTestClient -> EncryptionClient -> EncryptionServer -> SpeedTestServer`.
- `encryption_tcp_sandwich`
  Runs the encryption pair across one loopback TCP hop between `EncryptionClient` and `EncryptionServer`.
- `reality_direct_pair`
  Runs `SpeedTestClient -> RealityClient -> RealityServer -> SpeedTestServer` with a `google.com:443` visitor branch.
- `reality_tcp_sandwich`
  Runs the Reality pair across one loopback TCP hop between `RealityClient` and `RealityServer`, also using a
  `google.com:443` visitor branch.
- `mux_direct_pair`
  Runs `SpeedTestClient -> MuxClient -> MuxServer -> SpeedTestServer` to exercise mux overhead without socket adapters
  between the mux peers.
- `mux_tcp_sandwich`
  Runs each mux node behind a loopback `TcpListener`/`TcpConnector` pair so the mux peers communicate through TCP
  adapters.

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
8. optionally prints the captured `stdout.log` on success when `WATERWALL_TEST_SHOW_STDOUT_ON_SUCCESS=1` is set

So `run_waterwall_case.sh` is not a second testing system.
It is the small runner that powers each integration test invocation.

Success and failure are decided inside Waterwall:

- `TesterClient` / `TesterServer` detect mismatches and terminate the program on failure
- `TesterClient` logs the success marker on a passing run, and the helper accepts any worker count in that message
- `run_waterwall_case.sh` only watches for that success marker so it knows when the test is finished and can stop the
  still-running Waterwall process

`run_waterwall_speedtest.sh` is similar, but speedtests do not use `TesterClient`.
They pass when `SpeedTestClient` completes and Waterwall exits with status `0`.

## Showing stdout for passing tests

CTest only shows passing test output when the test writes to stdout/stderr and CTest is run in verbose mode.
The Waterwall integration runners normally keep successful runs quiet because they capture the process output in a
temporary `stdout.log`.

To print that captured log for successful runs:

```sh
WATERWALL_TEST_SHOW_STDOUT_ON_SUCCESS=1 \
  ctest --preset linux-gcc --verbose -R '^waterwall\.tls_roundtrip$'
```

For VS Code CMake Tools, add this to `.vscode/settings.json`:

```json
{
  "cmake.testEnvironment": {
    "WATERWALL_TEST_SHOW_STDOUT_ON_SUCCESS": "1"
  }
}
```

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
