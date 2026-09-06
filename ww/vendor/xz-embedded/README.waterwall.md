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
configuration, and this file. To refresh, check out the desired
upstream commit, copy the files above, format the C/headers, and update the pin.
No download or system liblzma lookup occurs during builds.

`XZEmbedded::XZEmbedded` (`xz_embedded`) is always a static library, built and
linked directly by `Waterwall` on every platform. Other targets use
`target_link_libraries(my_target PRIVATE XZEmbedded::XZEmbedded)` and
`#include <xz.h>`. The `ww` target does not export this dependency. Normal static
linker elimination of unused code still applies.

The compiled decoder supports XZ + LZMA2 + x86 BCJ with CRC32 integrity checks
and only the `XZ_SINGLE` allocation mode. CRC64, SHA-256, other BCJ filters,
multi-call allocation modes, and concatenated-stream support are disabled.
The pinned CRC64 and SHA-256 sources remain in the vendor copy but are not built.
Unsupported filters and integrity checks are rejected.
This library only decompresses; it does not provide compression or liblzma's API.
Call `xz_crc32_init()` once before concurrent decoder use; its table initialization
is not thread-safe. Use `xz_dec_init(XZ_SINGLE, 0)` with enough output space for the
complete payload. See `include/xz.h` for the single-call decoder lifecycle.
