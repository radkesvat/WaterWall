The QUIC dependency embedding retains the following upstream components. Normal
builds fetch immutable, SHA-256 checked source archives; their licenses are copied
into `licenses/` and remain present in the downloaded sources.

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
variant member. The WebTransport field table uses aggregate entries to retain
constant initialization with MSVC; its names and member pointers are unchanged.
The QUICHE structured-header and ACK-timestamp sources likewise use brace
initialization for token, byte-sequence, and timestamp-encoder aggregates,
preserving string copy/move, variant selection, and the timestamp exponent.
The QUICHE config source also uses `const` for its empty static option vector,
since libstdc++ 11 does not yet support literal `std::vector` instances. This
adaptation is generated in the build tree and preserves the read-only list.
The WebTransport header parser's unsupported-template-branch assertion is made
dependent for the same pre-CWG2518 compilers; its accepted types stay unchanged.

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
