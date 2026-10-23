# VMess independent-client interoperability

The explicit registrations in `tests/cmake/integration/vmess.cmake` invoke
`tests/vmess_interop.py` in the existing private network namespace. Inputs are
generated in the support library's private run directory, rather than copied
from this directory. WaterWall, the pinned V2Ray client and application peers
communicate only over loopback; public DNS and internet connectivity are unused.

Provision the reference before entering the namespace:

```sh
cmake --build --preset linux --target waterwall_vmess_reference
ctest --preset linux -R '^waterwall\.vmess_' --output-on-failure
```

The setup target uses `tests/provision_vmess_reference.py`. It downloads V2Ray
5.53.0's official Linux x86_64 or aarch64 archive, verifies its pinned SHA-256,
and extracts only `v2ray` into `build/test-tools/v2ray-5.53.0`. Tests never download
dependencies. `WATERWALL_VMESS_REFERENCE` may select an already-provisioned 5.53.0
binary. A missing or wrong-version reference fails the affected test explicitly.

The matrix covers local UUIDs and AuthenticationClient users; AES-128-GCM,
ChaCha20-Poly1305, `none`, and `zero` TCP; and the first three modes over UDP.
`zero` carries an unframed stream and has no supported UDP interpretation.
TCP verifies server-first output, 256 KiB of exact bidirectional bytes across
many records, and shutdown with the connection still alive. UDP verifies five
distinct nonempty datagrams and exact replies. Empty protocol records are
termination signals and are not tested as empty datagrams.

Additional cases reject a wrong UUID without contacting the protected target,
corrupt the encrypted header length after a valid AuthID without reaching fallback,
exercise managed connection limits, split initial wire bytes on two workers,
verify exact unauthenticated fallback replay, and compose TLS, WebSocket, and
WebSocket-over-TLS through existing nodes. The TLS fixture uses its local test
certificate with the reference client's certificate verification disabled; it
tests transport composition, not trust validation. VMess itself has no TLS or
HTTP settings.

The tests require native Linux namespaces (`unshare`, `ip`), Python 3, the built
WaterWall executable and the reference binary. Success requires exact payload
checks and WaterWall's orderly SIGTERM exit status 143. Each case has a 75-second
CTest bound; logs/configurations remain available on failure. These functional
tests make no throughput or 100,000-user scaling claim; native protocol and
authentication suites own deterministic crypto, replay, nonce and table tests.
