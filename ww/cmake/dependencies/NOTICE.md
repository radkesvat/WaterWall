The QUIC and GameNetworkingSockets dependency embeddings retain the following
upstream components. Normal builds fetch immutable, SHA-256 checked source
archives; their licenses are copied into `licenses/` and remain present in the
downloaded sources.

| Component | Pinned identity | License |
| --- | --- | --- |
| Google QUICHE | `0ded66479add86dae9ae2039bb78c25d4f04c535` | BSD, `licenses/quiche-LICENSE` |
| Abseil | `20260107.0` | Apache 2.0, `licenses/abseil-LICENSE` |
| Protocol Buffers lite and native protoc | `31.1` | BSD, `licenses/protobuf-LICENSE` |
| UTF-8 range (protobuf dependency) | bundled with protobuf `31.1` | MIT, `licenses/utf8-range-LICENSE` |
| Google URL/base/polyfills | `94ff147fe0b96b4cca5d6d316b9af6210c0b8051` | BSD, `licenses/googleurl-LICENSE` |
| Google URL ICU UTF helpers | bundled with Google URL | ICU, `licenses/googleurl-icu-LICENSE` |
| Google URL Mozilla parser | bundled with Google URL | BSD, `licenses/googleurl-mozilla-LICENSE` |
| zlib | `1.3.1` | zlib, `licenses/zlib-LICENSE` |
| Valve GameNetworkingSockets | `d534c19aa760df3fb75fd20db13ba1932b8a5463` | BSD 3-Clause, `licenses/gamenetworkingsockets-LICENSE` |
| WaterWall's prefixed BoringSSL | Chromium `154.0.8037.97`, `ac39ea6853833c1f18fd23614091d11855e71752` plus existing WaterWall patches | `tunnels/TlsClient/boringssl/LICENSE` |

`quiche.cmake` embeds the upstream production `quiche_core` source/dependency
target, including its three lite protos and standalone platform implementations.
It excludes test, tool, fuzzing, QBONE, MOQT and auxiliary target groups. Raw QUIC
sessions do not instantiate HTTP sessions. Google URL uses the upstream
`url_idna_ascii_only.cc` implementation and does not link ICU.

Generated Google URL header overlays retain GCC 11 support: literal-only
template guards use a dependent assertion, and the GURL ordering function does
not require libstdc++'s newer constexpr string comparison. The downloaded source
is unchanged; these adaptations preserve runtime behavior. Clang 14 support
adds explicit `typename` to dependent numeric aliases and uses brace initialization
for the checked iterator's pointer aggregate, including fixed and dynamic spans.
The pointer values, iterator checks, and numeric conversions stay unchanged.
For MSVC, the standalone URL subset omits Chromium's compiler-policy rejection,
uses an attribute query accepted by MSVC, and selects the existing portable
checked/clamped arithmetic instead of GNU overflow intrinsics. Windows ARM64
NEON detection recognizes `_M_ARM64`; numeric and iterator checks remain enabled.
Windows QUICHE builds and header consumers define `NOMINMAX`, `NOGDI`, and
`WIN32_LEAN_AND_MEAN` to keep Windows macros out of C++ and logging identifiers.
MSVC consumers enable the conforming preprocessor for QUICHE's C++20 status
macros. Two out-of-line defaulted comparisons explicitly compare their sole
variant member. WebTransport field bindings use ordinary pointers into each
call's header instead of constant-initialized member pointers rejected by MSVC
on x64/ARM64. Names, field order and const serialization are preserved, with no
global initialization.
The QUICHE structured-header and ACK-timestamp sources likewise use brace
initialization for token, byte-sequence, and timestamp-encoder aggregates,
preserving string copy/move, variant selection, and the timestamp exponent.
The QUICHE config source also uses `const` for its empty static option vector,
since libstdc++ 11 does not yet support literal `std::vector` instances. This
adaptation is generated in the build tree and preserves the read-only list.
The WebTransport header parser's unsupported-template-branch assertion is made
dependent for the same pre-CWG2518 compilers; its accepted types stay unchanged.

`gns.cmake` embeds the GameNetworkingSockets client library for plain UDP
connections, built on the same protobuf-lite, Abseil and prefixed BoringSSL as
QUICHE. `protobuf.cmake` holds the protobuf, Abseil and native protoc setup that
both embeddings use. The source list follows upstream `src/CMakeLists.txt`. It
excludes the ICE and WebRTC transports, `ISteamNetworkingMessages`, the flat C
interface, tests, examples and tools; `steamnetworkingsockets_p2p.cpp` is
compiled because the public interface refers to it.
Upstream's `steamnetworkingsockets_socketthread.cpp` is not compiled.
`tunnels/Internals/GnsCommon/transport/steamnetworkingsockets_externaltransport.cpp`
takes its place: it keeps upstream's service thread, thinker scheduling and
socket-sharing code, hands every outgoing datagram to a callback, receives
datagrams through a function call, and wakes the service thread with a mutex
and condition variable. The archive references no OS socket function, and each
block of that file names the upstream lines it was copied or adapted from. It
leaves out upstream's fake-network simulation and its hold queue for
out-of-order packets, which nothing in the open-source library calls: every
datagram is processed in the call that delivers it. On Windows it keeps
upstream's `timeBeginPeriod(1)` for the service thread's millisecond sleeps.
The library is built at upstream's release self-check level
(`STEAMNETWORKINGSOCKETS_SNP_PARANOIA=1`) in every configuration, because the
debug level validates the whole in-flight packet map on every packet.
Six generated overlay files adapt the downloaded sources, which stay unchanged.
The three message definitions select `LITE_RUNTIME`.
`steamnetworkingsockets_certs.cpp` tests unknown fields with `empty()`, because
protobuf-lite keeps them as a string. `crypto_digest_opensslevp.cpp` computes
HMAC-SHA256 with the one-shot `HMAC()` that its SHA-1 variant already uses,
because BoringSSL has no `EVP_PKEY_new_mac_key`. `opensslwrapper.cpp` skips the
custom `RAND` method and `CRYPTO_cleanup_all_ex_data` under
`OPENSSL_IS_BORINGSSL`. Each replacement must match its upstream text exactly
once, or the configuration stops.

Runtime dependencies use WaterWall's compiler/runtime, CPU and IPO policy.
BoringSSL builds the linked `ssl`/`crypto` targets; its unused
`pki` and `decrepit` targets are excluded from the default build.
On MSVC, the embedding removes BoringSSL's private `_HAS_EXCEPTIONS=0` override
so its STL exception classes share the application's and QUICHE's ABI.
A separate native CMake host build produces the matching protoc without target
toolchain, CPU, sanitizer or IPO flags; cross builds execute only this host tool.
Its pinned sources are staged once under the shared host-build identity, so
runtime build directories do not change the host compiler's source paths.
The staged host protobuf sources backport upstream
[`3b1ba48c`](https://github.com/protocolbuffers/protobuf/commit/3b1ba48c73767c4bab099a91f63d3b20e04750f0):
the JSON field map holds its recursive variant through `std::unique_ptr`, avoiding
incomplete-type instantiation with MSVC and older Clang in C++20. Access and
insertion follow the upstream fix, preserving repeated-field moves. The source
cache and runtime protobuf-lite sources remain unchanged.
