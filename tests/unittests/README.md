# Waterwall Unit Tests

These tests exercise small library-level behavior without launching the `Waterwall` process or the integration harness.

## Current Tests

- `waterwall.aes256gcm_unit`
  Verifies the `aes256gcm` wrapper through successful encryption/decryption, empty associated data, wrong-key failure,
  wrong-associated-data failure, and tampered-ciphertext failure. If the selected crypto backend or CPU does not expose
  AES256-GCM, the test exits successfully after reporting that the AES-specific cases were skipped.
- `waterwall.crypto_primitives_unit`
  Verifies generic `wcrypto` BLAKE2s, X25519, ChaCha20-Poly1305, and XChaCha20-Poly1305 vectors.
- `waterwall.capture_linux_nfqueue_unit`
  Verifies the Linux NFQUEUE netlink parser with synthetic messages, including capture-length byte order,
  malformed attributes, payload cursor exposure, and truncated-prefix packet-id recovery.
- `waterwall.select_fd_range_unit`
  Verifies the POSIX select backend rejects descriptors outside `fd_set` bounds while accepting the highest valid
  descriptor.
- `waterwall.select_registration_failure_unit`
  Verifies select registration failures close owned reads, listeners, and connections, roll back connection state, and
  release borrowed event wrappers without closing their descriptors.
- `waterwall.tcp_over_udp_fec_unit`
  Verifies the TCP-over-UDP Reed-Solomon FEC helper directly, including one missing data shard recovery, encoder reset
  after a failed parity emit callback, and malformed packet rejection.
- `waterwall.nghttp2_large_recv_unit`
  Verifies the bundled nghttp2 can consume one contiguous HTTP/2 input buffer larger than 32 KiB while preserving DATA
  callbacks. The Waterwall HTTP tunnels still feed nghttp2 in smaller slices defensively.
- `waterwall.tlsclient_alpn_unit`
  Verifies TlsClient's default and configured ALPN wire encoding, exact configured order, empty-list disable mode, and
  rejection of malformed or duplicate protocol lists. It also performs a real in-memory BoringSSL client/server
  handshake and proves that an HTTP/1.1-only TlsClient context negotiates `http/1.1`.
- `waterwall.ipmanipulator_tcpbit_unit`
  Verifies `IpManipulator` TCP-bit rewriting handles the full TCP flags byte, including downstream CWR/ECE handling and
  carried original flag restore.
- `waterwall.ipoverrider_node_gate_unit`
  Verifies the root-level `IpOverrider` `chance` and `only120` gates control the complete source/destination rewrite
  action in both directions, including the exact 120-byte boundary, unchanged forwarding, and round-robin cursor
  behavior when either gate rejects a packet.
- `waterwall.router_sniffing_unit`
  Verifies Router sniffing config, Host/:authority/SNI classification behavior, protocol bits, HTTP upgrade attributes,
  cleartext HTTP/2 authority sniffing, and protected QUIC/HTTP3 Initial SNI vectors when Router QUIC sniffing is compiled
  in. The QUIC vector generator is kept at `tests/unittests/fixtures/router_quic_sni/gen_quic_sni_vectors.go`; generated
  binary vectors are checked in under `tests/unittests/fixtures/router_quic_sni/vectors`.

## Running Unit Tests

Unit tests use a dedicated multi-configuration no-LTO build tree. Release retains
normal optimization, `NDEBUG`, ABI, and feature definitions; Debug enables
assertions and other Debug guardrails. The production Release tree remains
IPO/LTO-enabled and must not be reused for native unit tests. These configurations
are complementary: Debug is preferred first during behavioral iteration, while
Release proves the optimized behavior that ships.

Build and run the complete unit suite in both configurations:

```sh
cmake --preset linux-unit-tests
cmake --build --preset linux-unit-release
ctest --preset linux-unit-release --output-on-failure

cmake --build --preset linux-unit-debug
ctest --preset linux-unit-debug --output-on-failure
```

The registered no-LTO policy is intentionally small. It checks the configured
unit-tree options, the reachable compile/link commands, and representative
artifacts from WaterWall, lwIP, and TlsClient. It is a regression check for the
property that caused the slow links; it is not a toolchain attestation or a
reproducible-build system.

For a focused behavioral change, run the relevant test selection in Debug first so
assertions fail close to the violated contract, then repeat it in Release. Broad or
shared changes run both complete presets. Debug does not replace Release,
AddressSanitizer, UndefinedBehaviorSanitizer, or ThreadSanitizer coverage.

The unit CTest entries run through `run_unit_test.cmake`, which brings the requested unit executable up to date for the
active CTest configuration before running it. A complete validation also builds
the normal production Release lane and runs its integration, smoke, and policy
coverage against the IPO/LTO-enabled `Waterwall` executable.

The exhaustive network-runner source/workflow analyzer runs in the production
lane and is not repeated in the unit tree.

On macOS and Windows, `waterwall_platform_unit_tests` is the corresponding
native aggregate. CI builds that aggregate, runs the same direct no-LTO policy,
and then executes the registered tests carrying the `unit` label.

## Adding A Unit Test

1. Add the source file under `tests/unittests`.
2. Add an executable and a matching `add_test` entry in `tests/unittests/CMakeLists.txt`.
3. Add the executable as a dependency of `waterwall_unit_tests`.
4. Give the CTest entry the `unit` label plus any focused labels that help selection.
5. Document the new test in this file.
