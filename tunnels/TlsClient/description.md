<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/tls-client.mdx, and both files must keep the same documentation version.
-->

# TlsClient Node

`TlsClient` is a client-side TLS wrapper built on the bundled BoringSSL code in this repository.

It takes cleartext payload from the previous tunnel, encrypts it into TLS records for the next tunnel, and decrypts downstream TLS records back into cleartext.

This node is meant for the client side of a chain, usually between an application protocol tunnel and a transport adapter such as `TcpConnector`.

This node does a real Tls hadshake and mimics chorme behaviour, verified with JA4 hash and built with help of wireshark and inspecting chromes behaviour. it uses the exact libraries used in google chrome to do this (BoringSSl, LibBrotli)


## What It Does

- Creates a client-side TLS session for each Waterwall line.
- Sends a TLS ClientHello during upstream `Init`.
- Encrypts upstream payload with `SSL_write()`.
- Decrypts downstream payload with `SSL_read()`.
- Buffers application payload until the TLS handshake completes.
- Verifies peer certificates using a built-in CA bundle by default.

## Typical Placement

A common layout is:

- some cleartext-producing tunnel
- `TlsClient`
- `TcpConnector`

Example:

- `HttpClient -> TlsClient -> TcpConnector`

That arrangement lets:

- `HttpClient` produce plain HTTP
- `TlsClient` protect it with TLS
- `TcpConnector` carry the encrypted bytes to the remote server

## Configuration Example

```json
{
  "name": "tls-client",
  "type": "TlsClient",
  "settings": {
    "sni": "example.com",
    "verify": true,
    "ech-sni-trick": "example.net",
    "x25519mlkem768": true
  },
  "next": "tcp-connector"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TlsClient"`.

### `settings`

- `sni` `(string)`
  Required TLS server name indication.

  The current implementation rejects missing or empty `sni`.

## Optional `settings` Fields

- `verify` `(boolean, default: true)`
  Controls whether BoringSSL verifies the peer certificate chain.

  When this is left enabled:

  - peer verification stays enabled
  - the built-in CA bundle from `utils/cacert.h` is loaded into the TLS context

  When this is disabled:

  - `TlsClient` still performs a real TLS handshake
  - BoringSSL peer verification is disabled for that tunnel instance
  - certificate chain errors no longer fail the handshake at the TLS layer

- `ech-sni-trick` `(string)`
  When set, `TlsClient` generates a full fake TLS ClientHello using this hostname and embeds those bytes as the GREASE `encrypted_client_hello` payload before the outer ClientHello is serialized and hashed.

  The outer cleartext SNI remains `settings.sni`.

  The embedded fake ClientHello is generated with `x25519mlkem768` disabled, even if the outer tunnel keeps `x25519mlkem768` enabled. This keeps the embedded payload small enough for the packet-side trick while leaving the real outer ClientHello Chrome-like.

  Validation rules:

  - the field must not be empty

  This is intended for use with `IpManipulator`'s packet-splitting `ech-sni-trick`, so the bytes that `TlsClient` hashes are the same bytes that go on the wire.

- `x25519mlkem768` `(boolean, default: true)`
  Controls whether `TlsClient` advertises the `X25519MLKEM768` hybrid post-quantum group.

  When this is left enabled, the tunnel stays closer to current Chrome TLS behavior.

  If you disable it:

  - the generated ClientHello becomes smaller
  - the tunnel no longer mimics Chrome as closely
  - you lose the Chrome-like `X25519MLKEM768` key share behavior

Important current-implementation notes:

- a field named `alpn` exists in the source, but the active create path does not use a JSON ALPN value
- internal users can enable handshake takeover mode, check TLS handshake completion, and deinitialize per-line TLS resources after the handshake without closing the underlying Waterwall line. In that mode `TlsClient` becomes a raw pass-through after takeover.

## Tunnel API

`TlsClient` exposes an API that can generate a raw TLS ClientHello buffer.

Accepted request format:

- `generateTlsHello:<sni>`
  Generates a ClientHello using the tunnel's configured behavior.

Important note:

- the API follows the tunnel's `settings.x25519mlkem768` value
- if that setting is disabled, the generated ClientHello is smaller but less Chrome-like

## Detailed Behavior

### Startup and handshake flow

On upstream `Init`, `TlsClient`:

- creates per-line SSL state
- allocates memory BIOs
- switches the SSL object into client mode
- sets the configured SNI
- forwards upstream `Init` to the next tunnel
- immediately calls `SSL_connect()` to generate the first handshake flight

Any handshake bytes produced by BoringSSL are read from the write BIO and sent upstream to the next tunnel.

This is why `TlsClient` works well in chains such as:

- `SomeTunnel -> TlsClient -> TcpConnector`

The connector can buffer the ClientHello until the actual socket connect completes.

### `Est` versus TLS-ready state

In Waterwall terms, downstream `Est` still represents the underlying transport becoming established.

Current implementation detail:

- `tlsclientTunnelDownStreamEst()` simply forwards downstream `Est`
- TLS handshake completion happens later, inside downstream payload processing

So `Est` does not mean application data is already safe to send immediately on the wire as cleartext.
If the previous tunnel sends payload early, `TlsClient` buffers it until the handshake finishes.

### Upstream payload behavior

Before handshake completion:

- upstream payload is queued in a small buffer queue

After handshake completion:

- queued payload is flushed through `SSL_write()`
- new upstream payload is encrypted immediately
- resulting TLS records are read from the write BIO and forwarded upstream

If `SSL_write()` or BIO flushing fails:

- line state is destroyed first
- upstream `Finish` is sent
- downstream `Finish` is sent

### Downstream payload behavior

Downstream payload is treated as encrypted TLS record data from the network.

The tunnel:

- writes the encrypted bytes into the read BIO
- advances the handshake if the session is not finished yet
- flushes any handshake or protocol bytes generated by BoringSSL back upstream
- reads decrypted application bytes with `SSL_read()`
- forwards those cleartext bytes downstream toward the previous tunnel

When the TLS peer sends `END_STREAM`-equivalent closure or a fatal TLS error occurs, the tunnel destroys its line state and closes the Waterwall line.

### SSL context behavior

The tunnel creates one `SSL_CTX` per worker thread at tunnel construction time.

Current SSL context configuration includes:

- peer verification enabled by default, or disabled when `settings.verify` is `false`
- minimum protocol version TLS 1.2
- maximum protocol version TLS 1.3
- session cache mode enabled for client sessions
- GREASE enabled
- extension permutation enabled
- configured signature algorithms
- configured supported groups list
- signed certificate timestamps enabled
- Brotli certificate decompression support

When verification is enabled, the tunnel also loads a built-in CA certificate bundle from `utils/cacert.h`.

### Chrome-like handshake shaping

The source code intentionally tries to make the handshake look Chrome-like.

That includes:

- hardcoded ALPN list containing `h2` and `http/1.1`
- ALPS application settings for `h2` and `http/1.1`
  `h2` is the fixed Chrome payload `0x026832`, not a serialized HTTP/2 `SETTINGS` frame
- OCSP stapling extension
- signed certificate timestamp extension
- certificate compression support with Brotli

The bundled BoringSSL tree also contains local patches used by this tunnel.

## Notes And Caveats

- `TlsClient` is a client-side tunnel, not a TLS server.
- `downstream Init` is disabled in the current implementation and aborts if called.
- The tunnel does not open sockets by itself. Pair it with a transport such as `TcpConnector`.
- The active create path hardcodes a Chrome-like ALPN advertisement instead of using a user-provided ALPN list.
- `settings.verify` defaults to `true`; when disabled, certificate verification is skipped for that tunnel instance.
- `Est` reflects transport establishment, not TLS handshake completion.

## Advanced Details

This section is a programmer-facing summary of the concrete shaping work in `TlsClient` and its vendored BoringSSL copy.

### Baseline capture and fingerprint goal

The implementation work was driven by real Chrome captures and compared primarily against modern TLS fingerprints such as JA4.

- The practical target is Chrome-like behavior on the wire, not just using BoringSSL defaults.
- JA4 alignment matters more than JA3 for this tunnel because Chrome permutes extension order and JA3 is sensitive to that ordering.
- Matching JA3 exactly is not expected on every connection once extension permutation is enabled.

### Fixed ALPN advertisement

The active create path does not accept a user-provided ALPN list.

- `TlsClient` always advertises `h2` and `http/1.1`.
- This keeps the ALPN list stable and aligned with the Chrome-like handshake shaping in this node.

### TLS version and extension behavior

The SSL context is configured to stay in the same protocol band this tunnel was designed for.

- minimum protocol version is TLS 1.2
- maximum protocol version is TLS 1.3
- GREASE is enabled
- TLS extension permutation is enabled
- ECH grease is enabled on each `SSL` object
- if `settings.ech-sni-trick` is configured, the GREASE ECH payload is replaced with a generated fake ClientHello before the outer ClientHello is emitted
- OCSP stapling and signed certificate timestamps are enabled

### Cipher suite ordering patch

The bundled BoringSSL client handshake logic is patched so the advertised cipher suites follow a Chrome-style fixed order instead of BoringSSL's default selection logic.

- TLS 1.3 cipher order is forced
- TLS 1.2 cipher order is forced
- this change lives in the local `handshake_client.cc` patch
- the purpose is wire-level ordering control, not cryptographic behavior changes

### Supported groups and signature algorithms

The context also pins the advertised key exchange and signature preferences.

- supported groups are configured explicitly rather than using library defaults
- by default, that supported-groups list includes `X25519MLKEM768` to stay aligned with current Chrome-like behavior
- if `settings.x25519mlkem768` is set to `false`, the tunnel falls back to a non-`X25519MLKEM768` groups list and becomes less Chrome-like
- signature algorithms are configured explicitly in Chrome-like order
- this reduces drift across BoringSSL updates and keeps the ClientHello layout predictable

### Certificate compression support

Chrome supports Brotli certificate decompression, so this tunnel does too.

- the repo includes a local Brotli decompressor object for certificate decompression
- `SSL_CTX_add_cert_compression_alg` is used with Brotli decompression only
- compression is not offered for local certificate output, matching the intended client-side behavior here

### ALPS handling

ALPS needed special care because it is easy to feed the wrong bytes into the BoringSSL API.

- `SSL_add_application_settings` expects the raw per-protocol application settings value
- for `h2`, the configured payload is the fixed Chrome value `0x026832`
- for `http/1.1`, the configured payload is empty
- this value must not be replaced with a serialized HTTP/2 `SETTINGS` frame
- BoringSSL builds the final ALPS wire representation itself once the per-protocol values are configured

### CA verification and session behavior

The tunnel is still a real TLS client, not just a fingerprint shaper.

- peer verification is enabled by default and can be disabled with `settings.verify`
- when verification is enabled, CA roots are loaded from the built-in bundle in `utils/cacert.h`
- client session caching is enabled
- application data is buffered until the TLS handshake completes

### Vendored BoringSSL integration

The BoringSSL copy under `tunnels/TlsClient/boringssl` is used as a library dependency, not as a standalone product inside the Waterwall build.

- `crypto` and `ssl` are consumed as static libraries
- symbol prefixing is enabled so the vendored BoringSSL symbols do not collide with other OpenSSL-family code
- prefix header generation supports Go when available and falls back to Python when it is not

### Static-only build cleanup

The Waterwall build was also cleaned up so this subtree does not introduce extra executables.

- the vendored BoringSSL CMake now honors `BUILD_TOOL`
- `TlsClient` forces `BUILD_TOOL OFF`
- the `bssl` executable is therefore not created in the Waterwall build
- local CMake logic only touches the `bssl` target when that target actually exists
- the result is a static-library-oriented integration where `Waterwall` remains the only executable we want from this project path

## Prefixing BoringSSL Beside OpenSSL

This section is a step-by-step tutorial for how this project links both OpenSSL and BoringSSL statically in one final executable without symbol collisions.

### Why prefixing is needed

Both libraries export many of the same public symbol names such as `SSL_new`, `SSL_connect`, `X509_free`, and large parts of the ASN.1 and EVP APIs.

If you statically link plain OpenSSL and plain BoringSSL into the same executable:

- the linker will see duplicate global symbols
- one library may satisfy references intended for the other
- even if the link succeeds, runtime behavior can become undefined

The fix is to rebuild one of them with a unique symbol prefix. In this project, the vendored BoringSSL copy is the one that gets renamed.

### What this project does

The final `Waterwall` executable links:

- the main `ww` core, which may use OpenSSL as its crypto backend from [ww/CMakeLists.txt](/root/WaterWall/ww/CMakeLists.txt:497)
- the `TlsClient` tunnel, which links its own vendored BoringSSL static libraries from [tunnels/TlsClient/CMakeLists.txt](/root/WaterWall/tunnels/TlsClient/CMakeLists.txt:119)

The key design choice is:

- OpenSSL keeps its normal symbol names
- BoringSSL is rebuilt with the prefix `WW_BSSL`

That means a normal OpenSSL function such as `SSL_new` and a vendored BoringSSL function such as `WW_BSSL_SSL_new` can coexist in the same final binary.

### Step 1. Keep the two dependency trees separate

Do not try to make one library pretend to be the other.

- the regular OpenSSL build is pulled in by the `ww` layer through `openssl-cmake`
- the BoringSSL build lives under `tunnels/TlsClient/boringssl`
- `TlsClient` links only against the vendored BoringSSL `crypto` and `ssl` targets

In this repo, those pieces are wired from:

- [ww/CMakeLists.txt](/root/WaterWall/ww/CMakeLists.txt:497)
- [tunnels/TlsClient/CMakeLists.txt](/root/WaterWall/tunnels/TlsClient/CMakeLists.txt:124)

### Step 2. Choose a unique BoringSSL prefix

Pick a short prefix that is unlikely to collide with anything else.

This project uses:

```cmake
set(WW_BORINGSSL_PREFIX WW_BSSL)
set(BORINGSSL_PREFIX ${WW_BORINGSSL_PREFIX})
```

That is configured in [tunnels/TlsClient/CMakeLists.txt](/root/WaterWall/tunnels/TlsClient/CMakeLists.txt:119).

### Step 3. Provide the symbol list BoringSSL should rename

BoringSSL needs a list of exported symbols that will be rewritten with the new prefix.

This project stores that list in:

- [tunnels/TlsClient/boringssl_symbols.txt](/root/WaterWall/tunnels/TlsClient/boringssl_symbols.txt)

and passes it to the vendored build with:

```cmake
set(BORINGSSL_PREFIX_SYMBOLS ${CMAKE_CURRENT_SOURCE_DIR}/boringssl_symbols.txt)
```

If you want to reproduce this yourself in another project, this symbol list is one of the most important files. Without it, the prefix build cannot be generated correctly.

This file must include architecture-specific exported assembly names too, not just the common C API. In this repo, that matters for ARM builds because BoringSSL exports plain AArch64 P-256 helpers such as `ecp_nistz256_mul_mont`, `ecp_nistz256_point_add`, `ecp_nistz256_ord_mul_mont`, the capability variable `OPENSSL_armcap_P`, and ARM crypto helpers such as `sha256_block_data_order_neon` and `gcm_ghash_neon`. If those names are missing from the list, the generated prefix headers will leave them untouched and the final link can still collide with OpenSSL.

### Step 4. Let BoringSSL generate prefixed headers

Once `BORINGSSL_PREFIX` and `BORINGSSL_PREFIX_SYMBOLS` are set, the vendored BoringSSL CMake generates helper headers that rewrite symbol declarations to the prefixed names.

In this repo, the generated files are placed under:

- `tunnels/TlsClient/<build-dir>/boringssl/symbol_prefix_include`

The relevant logic lives in [tunnels/TlsClient/boringssl/CMakeLists.txt](/root/WaterWall/tunnels/TlsClient/boringssl/CMakeLists.txt:88).

The actual generator is:

- Go path: `tunnels/TlsClient/boringssl/util/make_prefix_headers.go`
- Python path: [tunnels/TlsClient/boringssl/util/make_prefix_headers.py](/root/WaterWall/tunnels/TlsClient/boringssl/util/make_prefix_headers.py)

In Waterwall, the vendored BoringSSL build tries Go first when `GO_EXECUTABLE` is available. If Go is not available, it falls back to the Python script. Both generators do the same job: they read `boringssl_symbols.txt` and create the prefix-header files consumed by the build.

Generated files include:

- `boringssl_prefix_symbols.h`
- `boringssl_prefix_symbols_asm.h`
- `boringssl_prefix_symbols_nasm.inc`

Those generated headers are what make BoringSSL compile and export `WW_BSSL_*` symbols instead of the default names.

### Step 5. Add the generated prefix include directory to every BoringSSL consumer

This step is easy to miss.

Any target in your project that includes BoringSSL headers and calls BoringSSL APIs must see:

- the normal BoringSSL headers
- the generated symbol-prefix include directory
- the `BORINGSSL_PREFIX` compile definition

In this repo, that is done for both `TlsClient` and `DecompressBrotli` in [tunnels/TlsClient/CMakeLists.txt](/root/WaterWall/tunnels/TlsClient/CMakeLists.txt:126):

```cmake
target_include_directories(TlsClient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include
    ${WW_BORINGSSL_PREFIX_INCLUDE_DIR}
)
target_compile_definitions(TlsClient PRIVATE BORINGSSL_PREFIX=${WW_BORINGSSL_PREFIX})
```

and similarly for `DecompressBrotli`.

If a target links to prefixed BoringSSL but does not compile with the same prefix configuration, it will still emit calls to the unprefixed names and the build will fail or bind incorrectly.

### Step 6. Build BoringSSL as static libraries

The project keeps the vendored BoringSSL integration library-oriented.

- `BUILD_SHARED_LIBS OFF`
- `BUILD_TOOL OFF`
- `BUILD_TESTING OFF`
- `INSTALL_ENABLED OFF`

This is configured in [tunnels/TlsClient/CMakeLists.txt](/root/WaterWall/tunnels/TlsClient/CMakeLists.txt:36) and honored by the vendored BoringSSL CMake in [tunnels/TlsClient/boringssl/CMakeLists.txt](/root/WaterWall/tunnels/TlsClient/boringssl/CMakeLists.txt:44).

The reason is simple:

- we want `crypto` and `ssl`
- we do not want extra tools or executables from the vendored subtree in the Waterwall build

### Step 7. Link only the prefixed BoringSSL libraries into the tunnel

After the vendored subtree is added, the tunnel links against its static `crypto` and `ssl` targets:

```cmake
target_link_libraries(TlsClient PRIVATE ww BrotliDec DecompressBrotli crypto ssl)
```

This is in [tunnels/TlsClient/CMakeLists.txt](/root/WaterWall/tunnels/TlsClient/CMakeLists.txt:191).

Because those libraries were built with the `WW_BSSL` prefix, their exported symbols no longer collide with the OpenSSL symbols used elsewhere in the program.

### Step 8. Let the main program link its normal OpenSSL backend

The `ww` core still uses ordinary OpenSSL through imported CMake targets:

- `OpenSSL::SSL`
- `OpenSSL::Crypto`

That setup is in [ww/CMakeLists.txt](/root/WaterWall/ww/CMakeLists.txt:497).

So the final executable effectively contains:

- normal OpenSSL for the `ww` backend path
- prefixed BoringSSL for `TlsClient`

That is the whole trick.

### Step 9. Verify the dual-link design

When reproducing this pattern yourself, verify all of these:

1. OpenSSL-linked code compiles without any BoringSSL prefix definition.
2. BoringSSL-linked code compiles with `BORINGSSL_PREFIX=<your prefix>`.
3. BoringSSL consumers include the generated prefix include directory.
4. The final link has no duplicate symbol errors, including architecture-specific asm symbols on ARM.
5. Only the executable targets you actually want are generated.

In this repo, the expected result is:

- `Waterwall` is the final executable
- vendored BoringSSL contributes static `crypto` and `ssl`
- the extra `bssl` tool is not built

### Common mistakes

These are the mistakes most likely to break this setup:

- forgetting that the generated prefix headers come from `util/make_prefix_headers.py` or `util/make_prefix_headers.go`
- forgetting to set `BORINGSSL_PREFIX_SYMBOLS`
- forgetting to add architecture-specific exported symbols like `OPENSSL_armcap_P`, ARM `ecp_nistz256_*` entry points, or ARM SHA/GCM asm helpers to `boringssl_symbols.txt`
- linking prefixed BoringSSL but compiling consumers without `BORINGSSL_PREFIX`
- adding `boringssl/include` but forgetting `symbol_prefix_include`
- trying to mix unprefixed and prefixed BoringSSL objects in the same target
- assuming JA4 or handshake shaping work is related to symbol prefixing; it is not
- disabling the BoringSSL tool target in CMake but still referencing `bssl` properties unconditionally

### How to repeat this in another project

If you want to do this yourself from scratch, the shortest working recipe is:

1. Keep OpenSSL and BoringSSL as separate dependency trees.
2. Pick a unique BoringSSL prefix such as `MYAPP_BSSL`.
3. Prepare a symbol list file for BoringSSL renaming.
4. Run BoringSSL's prefix-header generator from `util/make_prefix_headers.go` or `util/make_prefix_headers.py` through CMake.
5. Configure the BoringSSL build with `BORINGSSL_PREFIX` and `BORINGSSL_PREFIX_SYMBOLS`.
6. Add both `boringssl/include` and the generated prefix include directory to every BoringSSL consumer.
7. Compile every BoringSSL consumer with `BORINGSSL_PREFIX=<same prefix>`.
8. Link the resulting static BoringSSL `crypto` and `ssl` libraries only where you need them.
9. Link ordinary OpenSSL normally in the rest of the program.
10. Build the final executable and confirm there are no duplicate symbol conflicts.

That is the complete pattern this repository uses.
