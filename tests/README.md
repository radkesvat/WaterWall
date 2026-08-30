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

### Test Lanes & Network Isolation

On Linux, ordinary integration tests run inside private user and network namespaces created without root privileges via `tests/run_in_network_namespace.sh` (`unshare --user --map-root-user --net`). When the privileged lane invokes the same wrapper as root, it retains the caller's user namespace and creates only a private network namespace (`unshare --net`); this preserves access to runner-owned workspace paths while keeping network isolation.
Both modes provide loopback-only isolation without public internet access, enabling parallel execution of deterministic functional tests without port collision.

Tests are organized into distinct execution lanes via `tests/run_test_lane.sh`:

- `support`: Production policy and harness tests (13 tests), run strictly serially.
- `functional`: Deterministic integration tests (152 tests) run concurrently in isolated network namespaces. Parallelism is calculated adaptively as `min(32, max(4, 4 * CPUs))` (e.g. 16 jobs on a 4-CPU machine). Override with `WATERWALL_INTEGRATION_TEST_JOBS`.
- `external`: Tests requiring live host network connectivity (e.g., `reality_google_roundtrip`). Runs strictly serially on host network.
- `speed`: Multi-stream speed tests (16 tests). Runs strictly serially (`RUN_SERIAL TRUE`) to avoid CPU and bandwidth contention.
- `privileged`: Tests requiring root/TUN permissions (`sudo -E`, 6 tests). Runs serially.
- `all`: Runs preflight, support (serial), functional (parallel), external (serial), and speed (serial) in sequence (182 tests total).
- `preflight`: Verifies the namespace capabilities required by the current caller (user + network namespaces for non-root, network namespace only for root).

### Performance Baseline & Post-Change Timings

| Test Suite / Lane | Pre-Isolation (Host Serial) | Post-Isolation (Parallel Lanes) |
|---|---|---|
| **Support Tests** (13 tests) | ~55s (serial) | **~55s** (serial) |
| **Deterministic Functional** (152 tests) | ~173s (sequential) | **~22–24s** (16 jobs on 4 CPUs) / **~71s** (1 CPU, 4 jobs) |
| **External Network** (1 test) | ~1s | **<1s** (serial) |
| **Speed Tests** (16 tests) | ~48s (sequential) | **~46–48s** (serial) |
| **Privileged Integration** (6 tests) | ~15s (sequential) | **~14–15s** (serial) |
| **Ordinary non-privileged production sequence (`all`)** | ~277s | **~127s (~2m)** (support + functional + external + speed, 182 tests) |

These are warm-build planning measurements from the 4-CPU reference host, not
portable performance guarantees. The `all` total includes the production
policy/harness checks; the native-unit tree remains separate. Complete production
plus the Release native-unit lane takes about 3.5 minutes including the privileged
lane; the Release unit portion measured a median ~74s across three warm
`linux-unit-release` runs. That measurement excludes the additional Debug unit
lane, which cloud CI runs in parallel. These values depend on hardware and build
state.

## Which runner should I use?

There are several valid ways to run tests:

- `tests/run_test_lane.sh functional build/linux Release`
  Recommended for running all functional integration tests in parallel.
- `tests/run_test_lane.sh all build/linux Release`
  Runs the complete non-privileged production suite in sequence (support, functional, external, speed).
- `ctest`
  Normal entry point for running specific tests by pattern or label.
- `tests/run_waterwall_case.sh`
  Low-level single-case runner for debugging.
- `tests/run_in_network_namespace.sh`
  Low-level namespace wrapper (`tests/run_in_network_namespace.sh <command> <args...>`).

## Current layout

- `unittests/`
  Unit-test sources and CMake registration.
- `cases/<name>/config.json`
  One Waterwall config file for a test case.
- `cases/<name>/workers.txt`
  Optional worker-count override for a case.
- `speedtests/<name>/config.json`
  One Waterwall config file for a SpeedTestClient/SpeedTestServer case.
- `run_in_network_namespace.sh`
  Wrapper executing test commands inside a private network namespace with `lo` configured; non-root callers also enter a mapped user namespace.
- `run_test_lane.sh`
  Unified test runner executing test lanes (`support`, `functional`, `external`, `speed`, `privileged`, `all`, `preflight`).
- `run_waterwall_case.sh`
  The low-level single-case runner.
  It runs `Waterwall` from the selected case directory, writes a generated `core.json`, watches the tester log, and fails
  on crash or timeout. Generated `stdout.log` and `log/` output remain in the case directory after the run.
  After the tester success marker, it waits briefly for Waterwall to exit naturally before terminating it, and still
  treats unexpected shutdown statuses as failures.
  The generated `core.json` uses `4` workers by default, unless the case directory provides `workers.txt`.
  The generated `core.json` uses the `client` RAM profile so stream cases are not bottlenecked by the minimal 4 KB
  large-buffer size.
- `run_waterwall_speedtest.sh`
  The low-level speedtest runner. It uses the same generated `core.json` pattern but treats Waterwall exit status `0` as
  success, because `SpeedTestClient` terminates the process when all streams complete. Generated logs remain in the
  selected speedtest directory after the run.
  If `speedtests/_shared/` exists next to the selected speedtest directory, the runner copies those shared fixtures into
  the selected speedtest directory for the run and removes only those generated fixture copies afterward.
- `cleanup_generated_outputs.sh`
  Optional manual cleanup helper for generated test logs, reports, transient `core.json` files, copied cert/key fixtures,
  and unit-test logs. CTest does not call it.
- `CMakeLists.txt`
  Registers test cases, wraps isolated tests in `run_in_network_namespace.sh`, and defines custom targets `check_waterwall_support_tests`, `check_waterwall_integration_tests`, `check_waterwall_external_integration_tests`, `check_waterwall_speedtests`, and `check_waterwall_tests`.

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
- `tls13_record_shaping_roundtrip`
  Verifies bidirectional TLS 1.3 record shaping with fixed padding and delay values, including ordered deferred close after
  all accepted tester payload bytes have crossed both TLS senders.
- `tlsclient_direct_close_probe`
  Uses a local TLS 1.2 peer behind a recording TCP relay to verify TlsClient direct-close policy: normal protected-side
  close emits no client alert, peer `close_notify` closes without a client response or FIN wait, corrupted records close
  promptly without a client alert, and certificate verification failure does not hang in shutdown.
- `tls_fallback_plaintext_probe_tcp_loopback`
  Verifies that plaintext first bytes reaching `TlsServer` over a real TCP loopback hop are forwarded to the configured
  fallback branch with the original bytes preserved, while the protected TLS branch points at an invalid connector.
- `tls_handshake_timeout_slow_drip`
  Uses a raw TCP probe to verify a TLS-looking slow-drip handshake is closed by `TlsServer`'s hard handshake deadline even
  though each byte arrives before the listener active-idle timeout.
- `tls_tlslike_invalid_probe_does_not_fallback`
  Uses a raw TCP probe and fallback sentinel to verify malformed TLS-looking first bytes close on the TLS path instead of
  being routed to fallback.
- `tls_tlslike_oversized_probe_does_not_fallback`
  Uses a raw TCP probe and fallback sentinel to verify oversized TLS-looking first bytes do not cross the fallback branch.
- `tls_fallback_rejects_sni_gate`
  Negative case: verifies `TlsServer` rejects a config that combines fallback with an exact SNI gate.
- `reality_google_roundtrip`
  Verifies `TesterClient -> RealityClient -> TcpConnector` and `TcpListener -> RealityServer -> TesterServer` across a
  real TCP loopback hop while the Reality visitor branch handshakes with `google.com:443`.
- `reality_v2_roundtrip`
  Verifies bidirectional Reality v2 operation through a local TLS 1.3 cover destination with automatic native
  `16384`-byte plaintext fragmentation, without depending on an external site.
- `reality_v2_tls13_post_handshake`
  Runs Reality through a controllable Python/OpenSSL TLS 1.3 cover server configured to emit exactly two session tickets.
  A record-aware relay requires both protected post-handshake ticket records after client Finished, while fixture counters
  require one completed cover handshake and one protected-chain request/response. This verifies that an emitted ticket
  flight does not break authenticated handoff; the paired BoringSSL unit test verifies that TlsClient consumes the records.
  A fixture that silently omits the tickets fails the case.
- `reality_v2_tls13_handoff`
  Forces TLS 1.3 with session tickets disabled and verifies an immediate bidirectional tester workload survives the
  REQUEST/ACK/CONFIRM transition. CONFIRM opens the protected chain and the original payload is delivered exactly once
  without relying on a post-handshake ticket.
- `reality_v2_tls13_wire_handoff`
  Repeats twelve authenticated handoffs through a keyless, record-aware relay. It checks that REQUEST, ACK, and CONFIRM
  occupy plausible TLS 1.3 application records with reviewed body lengths in `22..1172`, that the 36 sampled controls do
  not collapse to one public length, and that no handoff or application marker is visible. It also requires genuine
  protected cover-handshake records before ACK, REQUEST-before-ACK ordering, CONFIRM-before-application ordering, the
  negotiated TLS 1.3 cipher, and exactly one protected request/response per sample. The probe submits application bytes
  immediately; event ordering on the public stream proves they remain queued until after CONFIRM without classifying the
  randomly padded controls by public length. The post-handshake case likewise exercises RealityClient's pre-ACK queue.
- `reality_v2_tls13_transition_matrix`
  Runs a deterministic local TLS 1.3 endpoint behind separate destination- and public-wire relays. It covers zero, one,
  and two immediate tickets; a ticket released after REQUEST; byte-split and partial-boundary tickets; a ticket coalesced
  with ACK; cover application data and close_notify before ACK; segmented cover and control records; and independently
  corrupted REQUEST, ACK, and CONFIRM. It also substitutes a prior connection's sequence-zero REQUEST into a fresh
  session and requires session binding to reject it. The server runs with the minimum `sniffing-attempts: 1`, while relay
  evidence proves a genuine protected client Finished record precedes REQUEST. Each success requires an exact protected request/response, authenticated event
  ordering (`REQUEST < ACK < CONFIRM < application`), complete-record destination cutoff, and fixture evidence that the
  selected ticket/segmentation/coalescing action actually happened. Expected pre-confirm failures must not open the
  protected chain. The probe prints per-scenario transition timing and the sampled control-body-length histogram. Python's
  `ssl` API cannot initiate TLS 1.3 KeyUpdate, so both KeyUpdate modes remain deterministic real-BoringSSL unit coverage;
  cryptographic replay/reorder and inner control-identity checks likewise remain in the shared/control unit matrix.
- `reality_v2_tls12_roundtrip`
  Forces `ECDHE-RSA-AES128-GCM-SHA256` and verifies the multi-record TLS 1.2 AES-GCM profile with the `auto`
  server-nonce policy, including takeover after the real protected epoch.
- `reality_v2_tls12_cbc_roundtrip`
  Forces `ECDHE-RSA-AES128-SHA` to exercise TLS 1.2 CBC explicit-IV generation,
  block-aligned camouflage sizing, encrypted inner lengths, and filler validation in both directions on four workers.
- `reality_v2_tls12_gcm_sequence_roundtrip`, `reality_v2_tls12_gcm_counter_roundtrip`, and
  `reality_v2_tls12_gcm_random_roundtrip`
  Force AES-128/AES-256 TLS 1.2 GCM suites while exercising every explicit server-nonce policy
  with both Reality record-protection algorithms.
- `reality_v2_tls12_cbc256_roundtrip`
  Forces `ECDHE-RSA-AES256-SHA` and the `aes-gcm` Reality algorithm to cover the AES-256 CBC
  suite family under multi-worker load.
- `reality_v2_tls12_gcm_wire_camouflage`, `reality_v2_tls12_cbc_wire_camouflage`,
  `reality_v2_tls12_chacha_wire_camouflage`, and `reality_v2_tls13_wire_camouflage`
  Use a keyless recording relay to parse only public TLS bytes. They verify the selected ServerHello suite, TLS 1.2
  record headers, exact GCM/CBC body formulas, client GCM sequence continuation, frozen server GCM policy behavior,
  aligned CBC bodies, non-repeating CBC IVs, and the zero-prefix TLS 1.3/TLS 1.2 ChaCha native shapes. Client-initiated normal close
  must use raw FIN with no alert in either direction. Server-initiated normal close must emit exactly one profile-correct
  server `close_notify` before FIN, with no client response or response wait; the relay withholds server FIN and requires
  RealityClient to close its TCP side from the authenticated alert alone. The TLS 1.2 probes also close immediately
  after both protected Finished records and require no first-close-alert authorization. Mirrored authorized corruption
  exercises both detector roles: each emits one direction-correct fatal-shaped record and the receiver never answers it.
  The same probes retain cross-connection replay and reordering checks.
  The real BoringSSL fixture compares passive and accessor sequence state and captures `SSL_shutdown()` only as a public
  shape oracle for TLS 1.3 and full/resumed AES-128/256-GCM, AES-128/256-CBC, and ChaCha TLS 1.2 handshakes. It also
  verifies GCM close-record nonce continuation and fresh CBC close-record IVs; Reality does not copy its shutdown state
  machine.
  The real-handshake fixtures use the repository's RSA certificate; ECDSA and non-ECDHE advertised suite families are
  covered by the fixed ClientHello/profile-map unit test rather than a real certificate handshake.
- `waterwall.reality_close_lifecycle_unit`
  Uses synchronous fake neighbors to verify server/fatal Payload-before-Finish ordering, no reflection toward a finished
  side, raw-Finish behavior, Reality-owned cleanup after line death during final Payload, and fatal no-response/dominance
  behavior. Every record profile covers fragmented and coalesced alerts. A client consumes server `close_notify` without
  replying and immediately closes both sides even when the fake peer supplies no FIN. Generic
  first-alert authorization uses a fatal record; Pending/Visitor/destination teardown remains free of synthetic alerts.
  The same fixture injects `1`, `16383`, `16384`, `16385`, `32768`, and `32769` byte callbacks through both real send
  helpers for every profile, decrypts/reassembles every record, checks exact native body lengths, and proves re-entrant
  line death stops a multi-record send after the transferred record. A real BoringSSL TLS 1.3 client Finished fixture verifies
  that the one-shot pre-request cover allowance is initialized only after TLS 1.3 key derivation, consumed before re-entrant
  destination forwarding, never reset, and leaves the minimum configured sniffing budget available for later failed candidates;
  TLS 1.2 accounting remains unchanged.
- `reality_client_rejects_obsolete_max_frame_size`, `reality_server_rejects_obsolete_max_frame_size`
  Negative startup cases proving Reality v2 rejects the obsolete `max-frame-size` key instead of silently ignoring it.
- `waterwall.tlsclient_alpn_unit`
  Verifies TlsClient's ordered `alpns` encoding, Chrome-like absent-setting default, explicit empty-list disable mode,
  malformed-list rejection, and an in-memory BoringSSL negotiation in which an HTTP/1.1-only TlsClient context must
  negotiate `http/1.1`.
- `waterwall.tlsclient_close_lifecycle_unit`
  Uses synchronous fake neighbors and real TlsClient line state to verify direct-close lifecycle behavior: normal upstream
  and downstream finishes remain directional and payload-free, fatal close finishes upstream before downstream, line death
  during the first fatal finish suppresses the second finish, and handshake-takeover release remains payload-free.
- `reality_v2_aes_gcm_roundtrip`
  Verifies multi-record bidirectional Reality v2 operation with the `aes-gcm` record-protection algorithm.
- `reality_v2_replay_protection`
  Runs a byte-blind recording relay that first proves a valid protected roundtrip, then reflects the captured downstream
  record upstream, sends a captured client record without a handshake, and substitutes that old record after a fresh
  TLS handshake. The protected sink must observe exactly the one original request, which is what rejects all three
  replays at once.
- `reality_visitor_plaintext_probe`
  Verifies that non-TLS first bytes reaching `RealityServer` are immediately treated as visitor traffic instead of being
  held in the Reality sniff buffer.
- `reality_visitor_short_prefix_probe`
  Uses a raw TCP client and instrumented visitor sink to verify an impossible TLS prefix is forwarded before client FIN,
  while plausible one- through four-byte prefixes remain Pending while open and are delivered byte-for-byte before the
  visitor destination receives EOF. An invalid prefix followed by FIN is delivered exactly once.
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
- `sniffrouter_tls_sni_camouflage_probe`
  Verifies SNI routing with real-TLS cover fallback using a loopback probe: expected SNI completes through the protected
  `TlsServer` branch, while mismatched SNI, absent SNI, and plaintext HTTP on the public TLS port are routed untouched to
  the default cover fixture (which completes TLS with the observed SNI or returns an nginx-like 400 Bad Request error).
- `socks5_noauth_tcp_loopback`
  Verifies `Socks5Client` without credentials against `Socks5Server(no-auth=true)` across a real TCP proxy hop. The
  SOCKS request target is configured as `localhost` and resolved by
  `domain-strategy=resolve-domains-and-use-only-ipv4` before `Socks5Server` reaches the separate tester TCP listener
  through a `TcpConnector` using `dest_context`, so the case covers method `0x00` negotiation, client-side target
  resolution, and CONNECT target forwarding.
  It also proves `Socks5Server(udp=false)` remains valid behind a TCP-only listener and does not require a dynamic UDP
  provider.
- `socks5_udp_requires_dynamic_provider`
  Expected startup failure: `Socks5Server(udp=true)` behind a TCP-only `TcpListener` is rejected because the finalized
  preceding path has no dynamic `UdpListener`/`TcpUdpListener` provider.
- `socks5_udp_dynamic_endpoint_isolation_probe`
  Uses the real SOCKS5 wire protocol to open two same-IP UDP associations, verifies distinct dynamic relay ports and
  source-port pinning, then proves cross-association traffic, the old fixed listener port, and a closed association are
  rejected while the remaining association stays usable. It also checks a concrete foreign peer-IP hint is refused.
- `socks5_noauth_udp_loopback`
  Verifies `Socks5Client(protocol=udp)` without credentials against `Socks5Server(no-auth=true, udp=true)`. The proxy
  control endpoint is a shared `TcpUdpListener`/`TcpUdpConnector` port, while the server returns a dedicated dynamic
  UDP relay port. The client must negotiate `UDP ASSOCIATE` over TCP and then send tester payloads to the returned relay
  endpoint, not the TCP control port.
- `socks5_noauth_udp_encryption_loopback`
  Verifies the same dynamic relay behavior through
  `Socks5Client -> EncryptionClient -> TcpUdpConnector` and
  `TcpUdpListener -> EncryptionServer -> Socks5Server`. This guards that dynamic UDP ingress and replies traverse the
  normal encrypted chain instead of bypassing its middle tunnels.
- `socks5_noauth_udp_packet_balanced_connector_loopback`
  Verifies a dynamically negotiated SOCKS UDP relay remains authoritative even when the client-side `TcpUdpConnector`
  uses UDP packet balancing. It covers queued first payload replay as well as ordinary relay writes.
- `socks5_noauth_udp_router_connector_loopback`
  Verifies metadata-only `Router` selection initializes the proxy path for the SOCKS handshake, and that negotiated UDP
  relay authority survives Router's Init-time detected-protocol reset before reaching a packet-balanced
  `TcpUdpConnector`; the relay's dynamic `BND.PORT`, rather than the configured proxy port, is used.
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
- `trojan_local_password_router_tcp_loopback`
  Verifies `TrojanServer` local password allowlist mode accepts `settings.users`, records the matched local username and
  raw password on the line without a users database, and lets `Router` match both before forwarding to the tester TCP
  listener.
- `trojan_local_password_router_rejects_wrong_password`
  Negative case: verifies `Router` does not take a Trojan local-user route when the authenticated username matches but
  the configured password condition is wrong.
- `trojan_fallback_invalid_probe_tcp_loopback`
  Verifies an unauthenticated plaintext probe that is not a complete Trojan password in the first payload is forwarded
  to the configured fallback branch with its bytes preserved instead of being hard-closed by `TrojanServer`.
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
- `vless_uuid_domain_tcp_loopback`
  Verifies the same VLESS TCP path when the preserved destination context is a domain name, including keeping the
  decoded destination port intact before `TcpUdpConnector` resolves and connects.
- `vless_local_username_router_tcp_loopback`
  Verifies `VlessServer` local UUID allowlist mode accepts an object entry with `username`, records both username and
  canonical UUID password on the line, and lets `Router` match both before forwarding to the tester TCP listener.
- `vless_local_username_router_rejects_wrong_password`
  Negative case: verifies `Router` does not take a VLESS local-user route when the authenticated username matches but
  the UUID password condition is wrong.
- `vless_fallback_invalid_probe_tcp_loopback`
  Verifies an unauthenticated plaintext probe that does not provide the complete VLESS UUID in the first payload is
  forwarded to the configured fallback branch with its bytes preserved instead of being hard-closed by `VlessServer`.
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
- `tcpudp_udp_over_tcp_tcp_roundtrip`
  Verifies that a TCP-origin line through `TcpUdpListener -> UdpOverTcpClient -> TcpConnector` re-enters
  `UdpOverTcpServer -> TcpUdpConnector` as TCP.
- `tcpudp_udp_over_tcp_udp_roundtrip`
  Verifies that a UDP-origin line through the same UdpOverTcp carrier re-enters `TcpUdpConnector` as UDP.
- `tcpudp_udp_over_tcp_large_udp_roundtrip`
  Verifies that the same UDP-origin sandwich preserves iperf-sized UDP datagrams larger than the 1500-byte small-buffer
  path.
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
  Verifies that `UdpConnector` accepts `balance-mode: "packet"` with multiple weighted `localhost` domain targets,
  resolves those targets through the local domain-resolution path, and preserves packet integrity while balancing packets across several UDP loopback
  listener ports.
- `udp_connector_listener_packet_loss_multiworker`
  Verifies a real UDP loopback hop across four workers using
  `PacketSender -> PacketsToStream -> UdpConnector` on the sender side and
  `UdpListener -> StreamToPackets -> PacketReceiver` on the receiver side, with the packet-analysis report requiring
  zero loss.
- `udp_listener_connector_packet_loss_multiworker`
  Verifies a two-hop UDP loopback path across four workers with explicit packet/stream bridges at the outer edges and
  a middle `UdpListener -> UdpConnector` chain, exercising listener-created Layer-4 lines that immediately feed another
  UDP connector, with zero packet loss required.
- `udp_listener_multiport_socket_packet_loss_multiworker`
  Verifies `UdpListener` with the socket multiport backend across four workers while a bridged Layer-4 `UdpConnector`
  sends to an integer destination port inside the listener's port range, with zero packet loss required.
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
  Verifies a direct `TesterClient -> PingClient -> PingServer -> TesterServer` packet chain in both directions,
  including fresh IPv4/ICMP Echo Requests, exact Echo Reply acknowledgements, nested synchronous reply handling,
  and one-time inner-packet delivery.
- `ping_legacy_settings_rejected` / `ping_server_legacy_settings_rejected`
  Verify that both strict Ping parsers reject removed wire-v1 settings with the explicit migration diagnostic.
- `packet_analysis_ping_roundtrip`
  Verifies PingClient's one-way fresh IPv4/ICMP Echo Request encoding over the packet analysis path.
- `ping_direct_real_adapters_roundtrip`
  On privileged Linux hosts, injects a wrapped ICMP request through the real
  `RawSocket -> PingServer -> TunDevice` server topology, verifies the immediate exact Echo Reply, then verifies the
  kernel-generated response returns in a separate Echo Request followed by a matching acknowledgement.
- `ipmanipulator_tcp_custom_protocol_roundtrip`
  Verifies that `IpManipulator` can rewrite the IPv4 TCP protocol number to a non-TCP/UDP custom value.
- `ipmanipulator_udp_custom_protocol_roundtrip`
  Verifies the equivalent custom protocol-number mapping for UDP.
- `ipmanipulator_tcp_custom_protocol_transport_roundtrip`
  Verifies two chained upstream `IpManipulator` nodes wrap TCP in a custom protocol and then explicitly unwrap it back
  to valid TCP before `TesterServer` sees it.
- `ipmanipulator_tcp_custom_protocol_transport_bridge_roundtrip`
  Verifies a TCP packet mapped to a custom protocol crosses a `Bridge`, then is restored downstream to valid TCP before
  `TesterServer` sees it.
- `halfduplex_roundtrip`
  Verifies that `HalfDuplexClient` and `HalfDuplexServer` split and reconstruct one logical line correctly.
- `http1_bidirectional_roundtrip`
  Verifies that single-mode `HttpClient(http1)` and `HttpServer(http1)` can stream request and response bodies at the
  same time when chained directly.
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
- `udp_over_tcp_direct_pair`
  Runs `SpeedTestClient(mode=udp) -> UdpOverTcpClient -> UdpOverTcpServer -> SpeedTestServer`, paced at
  `300 Mbits/sec` to stress UDP datagram framing without socket adapter effects.
- `udp_over_tcp_udp_sandwich`
  Runs `SpeedTestClient(mode=udp) -> UdpConnector`,
  `UdpListener -> UdpOverTcpClient -> TcpConnector`,
  `TcpListener -> UdpOverTcpServer -> UdpConnector`, and
  `UdpListener -> SpeedTestServer`, paced at `300 Mbits/sec` to exercise pure UDP-facing traffic over a TCP carrier.
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
important for validating bidirectional transports such as the HTTP cases above.

## Running locally

Production integration tests and native unit tests deliberately use separate
build trees. The production Release tree keeps IPO/LTO enabled. The native-unit
tree disables IPO/LTO and supports complementary Release and Debug configurations.

```sh
# Complete production Release lane: integration, smoke, and source-policy coverage.
cmake --preset linux-gcc-x64
cmake --build --preset linux-gcc-x64 --config Release --target check_waterwall_tests

# Native units: optimized Release behavior without IPO/LTO.
cmake --preset linux-unit-tests
cmake --build --preset linux-unit-release
ctest --preset linux-unit-release --output-on-failure

# Native units: assertions and Debug guardrails without IPO/LTO.
cmake --build --preset linux-unit-debug
ctest --preset linux-unit-debug --output-on-failure
```

Important:

- run commands from the repo root
- `ctest --preset linux-gcc` reads the production `build/linux-gcc-x64` tree,
  while `ctest --preset linux-unit-release` reads `build/linux-unit-tests`; do
  not mix the two lanes
- `linux-gcc` and `linux-unit-release` select `Release`; `linux-unit-debug`
  selects `Debug`. Use Debug first for relevant behavioral iteration, then run
  the same coverage in Release; broad/shared changes run both complete unit lanes
- direct `ctest` runs do not build missing executables.
  The Release unit preset builds `waterwall_unit_tests`. The registered policy
  directly checks that the unit tree has IPO disabled, reachable build commands
  do not enable LTO, and representative linked artifacts contain no embedded
  LTO IR. Build `Waterwall`, or one of the `check_waterwall_*` targets first,
  only when the scope requires the production lane too.
- crypto backend presets follow the same split. For example,
  `linux-sodium-crypto` builds the production binary and runs integration tests,
  while `linux-sodium-crypto-unit` builds and runs native units against the same
  backend without IPO/LTO. Production crypto presets intentionally do not expose
  native-unit targets.

Run one native-unit configuration independently when focusing a failure:

```sh
cmake --build --preset linux-unit-release
ctest --preset linux-unit-release --output-on-failure

cmake --build --preset linux-unit-debug
ctest --preset linux-unit-debug --output-on-failure
```

Run only integration tests:

```sh
cmake --build --preset linux-gcc-x64 --config Release --target check_waterwall_integration_tests
```

## What `run_waterwall_case.sh` does

When you run the helper script directly, it:

1. uses the selected case directory as the run directory
2. writes a generated `core.json`
3. launches the real `Waterwall` binary
4. waits for the built-in tester success log line
5. waits briefly for natural exit, then sends `SIGTERM` if Waterwall is still running
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

After a normal integration case logs the tester success marker, `run_waterwall_case.sh` waits up to `0.5` seconds for
Waterwall to exit naturally before sending `SIGTERM`. Override this when debugging shutdown paths:

```sh
WATERWALL_TEST_SUCCESS_EXIT_GRACE_SECONDS=5 \
  ctest --preset linux-gcc --output-on-failure -R '^waterwall\.tls_fallback_connector_target_tcp_loopback$'
```

## Showing stdout for passing tests

CTest only shows passing test output when the test writes to stdout/stderr and CTest is run in verbose mode.
The Waterwall integration runners normally keep successful runs quiet because they capture the process output in a
case-local `stdout.log`.

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

## Cleaning Generated Test Outputs

Generated test outputs are ignored by git and kept for debugging. To remove them manually:

```sh
tests/cleanup_generated_outputs.sh
```

Preview what would be deleted:

```sh
tests/cleanup_generated_outputs.sh --dry-run
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
