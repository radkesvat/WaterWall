# Waterwall Unit Tests

These tests exercise small library-level behavior without launching the `Waterwall` process or the integration harness.

## Current Tests

- `waterwall.aes256gcm_unit`
  Verifies the `aes256gcm` wrapper through successful encryption/decryption, empty associated data, wrong-key failure,
  wrong-associated-data failure, and tampered-ciphertext failure. If the selected crypto backend or CPU does not expose
  AES256-GCM, the test exits successfully after reporting that the AES-specific cases were skipped.
- `waterwall.users_sync_unit`
  Verifies user sync-index semantics and stress-tests the users database locking with concurrent update/pull loops and
  concurrent add/remove/export/pull loops. These cases are intentionally loop-heavy to shake out missed write locks,
  inconsistent pull snapshots, and stale `user_t` lifetime exposure.
- `waterwall.tcp_over_udp_fec_unit`
  Verifies the TCP-over-UDP Reed-Solomon FEC helper directly, including one missing data shard recovery, encoder reset
  after a failed parity emit callback, and malformed packet rejection.
- `waterwall.nghttp2_large_recv_unit`
  Verifies the bundled nghttp2 can consume one contiguous HTTP/2 input buffer larger than 32 KiB while preserving DATA
  callbacks. The Waterwall HTTP tunnels still feed nghttp2 in smaller slices defensively.

## Running Unit Tests

Build and run only the unit tests:

```sh
cmake --preset linux-gcc-x64
cmake --build --preset linux-gcc-x64 --target check_waterwall_unit_tests
```

Equivalent two-step form:

```sh
cmake --build --preset linux-gcc-x64 --target waterwall_unit_tests
ctest --preset linux-gcc --output-on-failure -L unit
```

The unit CTest entries run through `run_unit_test.cmake`, which builds the requested unit executable for the active CTest
configuration if it is missing. This keeps IDE test runners from failing just because they selected `Debug` while only
`Release` unit executables had been built.

## Adding A Unit Test

1. Add the source file under `tests/unittests`.
2. Add an executable and a matching `add_test` entry in `tests/unittests/CMakeLists.txt`.
3. Add the executable as a dependency of `waterwall_unit_tests`.
4. Give the CTest entry the `unit` label plus any focused labels that help selection.
5. Document the new test in this file.
