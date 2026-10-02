# Connection fisher encryption roundtrip


Exercises the connection fisher encryption roundtrip scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tester-client`: `TesterClient` → `connection-fisher-client`
- `connection-fisher-client`: `ConnectionFisherClient` → `enc-client`
- `enc-client`: `EncryptionClient` → `tcp-connector`
- `tcp-connector`: `TcpConnector` (terminal or independently bound endpoint)
- `tcp-listener`: `TcpListener` → `enc-server`
- `enc-server`: `EncryptionServer` → `connection-fisher-server`
- `connection-fisher-server`: `ConnectionFisherServer` → `tester-server`
- `tester-server`: `TesterServer` (terminal or independently bound endpoint)

CTest selections and overrides:

- `waterwall.connection_fisher_encryption_roundtrip` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: TesterClient must report that all worker lines completed successfully before the deadline. After that marker, the roundtrip runner accepts exit 0 or its expected SIGTERM status 143; early exit, a missing marker or another status fails.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.connection_fisher_encryption_roundtrip$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
