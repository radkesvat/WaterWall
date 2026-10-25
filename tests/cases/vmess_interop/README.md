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
packet writer frame is limited to 2048 bytes; this affects native UDP as well as
packetaddr. sing-box peer-limit cases use
14993/14981-byte IPv4/IPv6 payloads, derived from its pinned encrypted writer's
15000-byte plaintext chunk limit including the envelope. Its 65400-byte
protocol-limit cells are explicitly skipped: its writer splits the datagram and
its 16384-byte reader refuses the opposite direction. WaterWall pairs retain the
65400-byte workload, and native vectors/runtime fixtures cover exact codec maxima.

Exact 8 KiB means **8192 application payload bytes**, before any envelope, length,
authentication tag or padding. The size regressions keep WaterWall's full framing
capacity and record these separate pinned-peer constraints:

| Endpoint pair | Exact 8192-byte UDP workload |
| --- | --- |
| WaterWall ↔ WaterWall | Preserves the complete datagram and reply, using native UDP or packetaddr. |
| WaterWall ↔ sing-box 1.12.0 | Supported in both endpoint roles, using native UDP or packetaddr with AES. |
| WaterWall ↔ Xray 25.6.8 | Native UDP cannot carry this application size: its [authenticated writer](https://github.com/XTLS/Xray-core/blob/v25.6.8/common/crypto/auth.go#L249) bounds the entire frame to its [8192-byte buffer](https://github.com/XTLS/Xray-core/blob/v25.6.8/common/buf/buffer.go#L12), including length, tag and padding. |
| WaterWall ↔ V2Ray 5.53.0 | Neither native UDP nor packetaddr can carry this application size: its [authenticated writer](https://github.com/v2fly/v2ray-core/blob/v5.53.0/common/crypto/auth.go#L251) uses a [2048-byte buffer](https://github.com/v2fly/v2ray-core/blob/v5.53.0/common/buf/buffer.go#L10) for the complete frame. |

The peer-limit regressions first require a successful small control exchange, then
verify that the oversized workload cannot complete as an intact echo. Passing
such a negative case records the peer's known limitation; it is not a successful
large-datagram interoperability result. Do not lower WaterWall's own limits or
truncate/split a UDP application datagram to make those peers appear compatible.
The maximum usable payload depends on direction, framing profile and endpoint
implementation, and is separate from TCP stream transfer size.

Run these positive and negative size checks with
`ctest --preset linux --output-on-failure -R 'udp_size_(8k|limit)$'`.

See [Developer Guide Part 6](../../../WaterWall-Docs/docs/05-devguides/part6-build-test-review.mdx#vmess-independent-client-coverage)
for the peer matrix, focused Debug/Release and sanitizer commands, and dependency
closure checks. Tests require Linux namespaces (`unshare`, `ip`), Python 3,
WaterWall and the pinned references. Exact bytes, datagram boundaries, protected
backend admission and orderly SIGTERM exit status 143 are asserted. CTest bounds
are 75 seconds; logs/configurations remain on failure. These functional cases make
no throughput or 100,000-user scaling claim.
