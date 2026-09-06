# Build-time XZ encoder

This standalone native project builds `waterwall_xz_encoder` against upstream
liblzma via CPM, pinned to XZ v5.8.3 commit
`4b73f2ec19a99ef465282fbce633e8deb33691b3`.
Upstream: https://github.com/tukaani-project/xz/tree/4b73f2ec19a99ef465282fbce633e8deb33691b3

From this directory, using a native compiler and Ninja:

```sh
cmake --preset host
cmake --build --preset host-release -j8
ctest --preset host-release
../../../build/xz-encoder-host/Release/waterwall_xz_encoder INPUT OUTPUT.xz
```

On Windows, the executable has the `.exe` suffix. Use `host-debug` for the Debug
build and tests. To build only the encoder, add `--target waterwall_xz_encoder` to
the build command. The output path must not already exist. Read, encode, write,
or close failures return nonzero; an incomplete output is removed when possible.
Input and output are streamed through fixed 64 KiB buffers.

The host project is configured separately from Waterwall. Do not pass a target
cross-compilation toolchain or target `CC`/`CFLAGS` environment to this configure.
It rejects configurations that CMake identifies as cross-compiling. Its executable
and liblzma stay entirely outside the production target graph and are not
installed or packaged by Waterwall. No startup, loader, or packaging step is
connected here.

## Fixed payload format

- One XZ stream, with no trailing padding or concatenated streams.
- x86 BCJ followed by LZMA2; BCJ start offset zero.
- CRC32 integrity check.
- 8 MiB LZMA2 dictionary; `lc=3`, `lp=0`, `pb=2`.
- Normal mode, BT4 match finder, nice length 64, search depth 64.
- Single-threaded encoding, with no environment-derived encoder options.

The raw output is an `.xz` file. Packaging must separately retain its compressed
size and trusted expected uncompressed size. The tool accepts any input file;
it does not create or load a runtime module. Parameters live in `encoder.c` and
are not configurable on the command line.

## Portable decoder boundary

Production builds expose `WaterWall::XZDecoder` separately from `ww`, backed only
by the vendored XZ Embedded decoder. Include `<ww_xz_decoder.h>` and link that
target directly. Call `wwXzDecoderInit()` once before concurrent decoder use,
then `wwXzDecode(input, input_size, output, output_capacity, expected_size)`.

The caller supplies valid non-overlapping buffers and the expected output size.
The wrapper uses `XZ_SINGLE`, so the output buffer doubles as the dictionary;
only decoder state is allocated. It accepts CRC32 XZ with the built-in decoder's
LZMA2/x86 BCJ support, rejects other integrity checks, and requires
`XZ_STREAM_END`, exact output size, and complete input consumption. Raw
XZ Embedded also supports LZMA2 without BCJ. The encoder always selects x86 BCJ.
A typed status distinguishes unsupported data, malformed data, allocation failure,
insufficient output space, size mismatch, and trailing data. Discard output after
any failure. There are no filesystem, Linux, mapping, or loader dependencies in
the wrapper.

The native test builds a small module as an opaque input file, runs the actual
encoder, and decodes it with the same wrapper and XZ Embedded sources used by
Waterwall. It also covers empty input, input spanning multiple encoder buffers,
repeatability, truncation, corruption, CRC64 rejection, unsupported BCJ filters
and offsets, concatenation/padding, output bounds, wrong expected sizes, existing
output preservation, and missing input. No module is loaded or executed.
