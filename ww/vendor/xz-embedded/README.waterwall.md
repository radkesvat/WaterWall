# XZ Embedded in WaterWall

Upstream: https://github.com/tukaani-project/xz-embedded
Pinned commit: `ae63ae3a36ed01724674e8f3d750dc47bf125410` (2024-12-30).
License: 0BSD; see `COPYING` and `AUTHORS`.

This is the userspace decoder subset described by the upstream `README`:

- `linux/include/linux/xz.h` → `include/xz.h`
- `linux/lib/xz/{xz_crc32.c,xz_crc64.c,xz_sha256.c,xz_dec_lzma2.c,xz_dec_stream.c,xz_dec_bcj.c,xz_lzma2.h,xz_private.h,xz_stream.h}` → `src/`
- `userspace/xz_config.h` → `src/xz_config.h`
- `linux/Documentation/staging/xz.rst` → `xz.rst`
- `AUTHORS`, `COPYING`, and `README` retain their upstream names.

Local changes are C/header formatting with the repository's `clang-format` style
(preserving upstream include order), plus the added CMake integration, formatter
configuration, and this file. The stream-header/footer identifiers are also
customized: `src/xz_stream.h` uses the shared local `include/ww_xz_format.h`
constants (`MUFASA`, `gg`, and the CRC32 selector `FF`). The host encoder
includes that same header. `src/xz_dec_stream.c` normalizes the CRC32 selector
to `01` in its own header/footer buffers before CRC validation; standard `01`
selectors are rejected for CRC32 streams. The local `WW_XZ_SKIP_BLOCK_CRC32`
define omits only Block data CRC32 calculation and comparison, consuming the
stored check through the existing bounded skip helper. To refresh, copy the
pinned upstream sources, retain the identifier, selector and optional Block
CRC32 integration, format the C/headers, and update the pin.
No download or system liblzma lookup occurs during builds.

`XZEmbedded::XZEmbedded` (`xz_embedded`) is always a static library, built and
linked directly by the ordinary application on every platform. Other targets use
`target_link_libraries(my_target PRIVATE XZEmbedded::XZEmbedded)` and
`#include <xz.h>`. The `ww` target does not export this dependency. Normal static
linker elimination of unused code still applies.

`WW_PACKED_PAYLOAD_CRC32` defaults to `OFF`. With `WW_PACK_RUNTIME=OFF` and this option `ON`, CMake builds `ww_launcher_xz_embedded` from the same sources with
`WW_XZ_SKIP_BLOCK_CRC32` defined privately. `XZEmbedded::Launcher` selects that
engine for the launcher wrapper; otherwise it aliases the fully checking engine.
Ordinary decoder consumers keep all CRC checks. Both engines retain the selected
CPU compiler options and their existing relocation policy.

The compiled decoder supports the XZ container layout with Waterwall identifiers,
LZMA2 + x86 BCJ, and CRC32 integrity checks
and only the `XZ_SINGLE` allocation mode. CRC64, SHA-256, other BCJ filters,
multi-call allocation modes, and concatenated-stream support are disabled.
The pinned CRC64 and SHA-256 sources remain in the vendor copy but are not built.
Unsupported filters and integrity checks are rejected.
This library only decompresses; it does not provide compression or liblzma's API.
Call `xz_crc32_init()` once before concurrent decoder use; its table initialization
is not thread-safe. Use `xz_dec_init(XZ_SINGLE, 0)` with enough output space for the
complete payload. See `include/xz.h` for the single-call decoder lifecycle.

Standard `.xz` streams are rejected by this decoder. Standard XZ tools reject
Waterwall streams unless the magic and both CRC32 selectors are restored. The
header selector is at offset 7; the footer selector is three bytes before the
end of the stream. Both store `FF` instead of `01`. Reserved flag bytes stay zero.
The decoder does not modify caller input. Stream CRCs still cover the original
`00 01` flags. Stream header/footer, Block Header and Index CRCs are always
verified; only a launcher explicitly built with `WW_PACKED_PAYLOAD_CRC32=OFF`
skips Block data CRC32 verification.
Compressed bytes, field widths, indexes and stored checksum values are unchanged.
The magic fields themselves are not covered by XZ header/footer CRCs.
