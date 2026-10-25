# VMess independent interoperability

`tests/cmake/integration/vmess.cmake` registers both endpoint directions through
`tests/vmess_interop.py` and `tests/vmess_client_interop.py`. Each case owns its
processes, generated configuration and application sockets in a private loopback
network namespace. Tests use no public DNS or internet destinations.

Provision the checksum-pinned official V2Ray 5.53.0, Xray 25.6.8 and sing-box 1.12.0
references before entering namespaces:

```sh
cmake --build --preset linux --target waterwall_vmess_reference
ctest --preset linux -R '^waterwall\.vmess_' --output-on-failure
```

`tests/provision_vmess_reference.py` supports native Linux x86_64 and aarch64 and
extracts only each named executable after checking the archive SHA-256. Tests
check exact versions and never download peers. Already provisioned executables
can be selected with `WATERWALL_VMESS_REFERENCE`, `WATERWALL_VMESS_XRAY_REFERENCE`
and `WATERWALL_VMESS_SING_BOX_REFERENCE`. Missing or wrong-version peers make the
affected validation unavailable, never a successful interoperability result.

V2Ray retains the full existing local/managed TCP/UDP body-mode, framing,
destination, fallback and transport matrix. Xray and sing-box add representative
AES/ChaCha TCP/UDP coverage in both directions. Xray's public
`XRAY_CONE_DISABLED=true` explicitly selects native UDP instead of automatic XUDP;
XUDP and Mux.Cool remain excluded. WaterWall's separate Mux framing does not
provide either external protocol. Short IDs, auto selection, denied body security,
termination choices and registered APIServer stats have dedicated cases.

Long encrypted cases use 65540 stop-and-wait request/echo exchanges, forcing more
than 65536 real records in each direction on exactly one accepted transport.
AES/ChaCha cases include padded and authenticated-length framing. Strict cases
verify 65535 successful exchanges and closure before outgoing nonce reuse.
Additional zero/TLS TCP and NONE/TLS UDP cases make the reference verify the local
certificate; older transport-composition regressions retain their explicit
verification setting.

packetaddr cases cover IPv4/IPv6, two server destinations with interleaved replies,
bounded destination admission and empty datagrams. Native UDP empty records
remain termination signals. V2Ray's SOCKS inbound drops empty UDP before wrapping,
so only that peer-client cell is explicitly unsupported; its server accepts empty
packetaddr datagrams. V2Ray near-limit payloads are 1940 bytes because its complete
packet writer frame is limited to 2048 bytes. sing-box peer-limit cases use
14993/14981-byte IPv4/IPv6 payloads, derived from its pinned encrypted writer's
15000-byte plaintext chunk limit including the envelope. Its 65400-byte
protocol-limit cells are explicitly skipped: its writer splits the datagram and
its 16384-byte reader refuses the opposite direction. WaterWall pairs retain the
65400-byte workload, and native vectors/runtime fixtures cover exact codec maxima.

See [Developer Guide Part 6](../../../WaterWall-Docs/docs/05-devguides/part6-build-test-review.mdx#vmess-independent-client-coverage)
for the peer matrix, focused Debug/Release and sanitizer commands, and dependency
closure checks. Tests require Linux namespaces (`unshare`, `ip`), Python 3,
WaterWall and the pinned references. Exact bytes, datagram boundaries, protected
backend admission and orderly SIGTERM exit status 143 are asserted. CTest bounds
are 75 seconds; logs/configurations remain on failure. These functional cases make
no throughput or 100,000-user scaling claim.
