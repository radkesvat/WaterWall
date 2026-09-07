# Build-time payload tools

This standalone native project builds `waterwall_xz_encoder` against upstream
liblzma via CPM, pinned to XZ v5.8.3 commit
`4b73f2ec19a99ef465282fbce633e8deb33691b3`.
Upstream: https://github.com/tukaani-project/xz/tree/4b73f2ec19a99ef465282fbce633e8deb33691b3

The same project builds the CRT-only `waterwall_payload_tool` for ELF/PE
identification and embedding compressed bytes and size/target metadata in C.
Neither tool is linked into the launcher or the application.

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
installed or packaged by Waterwall. Packed builds invoke the native project via
`core/build_host_encoder.cmake`, whose CMake file lock covers configure and
build. Compiler/generator-specific caches keep incompatible host configurations
separate. Target compiler environment flags are removed while Windows MSVC
`PATH`, `INCLUDE`, `LIB`, and `LIBPATH` survive. The owning application runtime
interface is attached to the decoder only when that target exists; standalone
encoder/decoder tests have no application link dependency.

Automatic host builds set `BUILD_TESTING=OFF` and need no Python. The manual
`host` preset enables tests, which use Python to exercise the native tools and
the CMake packaging script. The Windows launcher smoke runner also remains Python.

`core/generate_packed_payload.cmake` owns staging, platform-specific stripping,
tool invocation and atomic publication. It validates the executable before and
after finalization, preserving the original application and any previously
published source on failure. A per-output lock protects the adjacent staging
directory across concurrent invocations; each configuration has its own output.
Only a completed `payload.c` is renamed into place. Both native tools create
output exclusively and remove incomplete output on write/close failure.

The payload helper can also be invoked directly:

```sh
waterwall_payload_tool validate TARGET EXECUTABLE
waterwall_payload_tool embed TARGET EXECUTABLE PAYLOAD.xz OUTPUT.c
```

`TARGET` is `linux-x86_64`, `windows-x86_64`, or `windows-x86`. The embedding
command expects the XZ bytes generated from that finalized executable by the
encoder. It does not strip, compress, execute, or publish files itself.

## Fixed payload format

- One stream with the XZ container layout, using `MUFASA` as its six-byte
  header identifier and `gg` as its two-byte footer identifier; neither includes
  a terminating NUL. No trailing padding or concatenated streams.
- x86 BCJ followed by LZMA2; BCJ start offset zero.
- CRC32 integrity check, represented by `FF` in both copies of the stream
  flags. Their reserved byte stays zero; stored header/footer CRCs cover `00 01`.
- 8 MiB LZMA2 dictionary; `lc=3`, `lp=0`, `pb=2`.
- Normal mode, BT4 match finder, nice length 64, search depth 64.
- Single-threaded encoding, with no environment-derived encoder options.

The intermediate files keep the `.xz` suffix but use Waterwall identifiers, so
standard XZ tools cannot decode them directly. Shared constants live in
`ww/vendor/xz-embedded/include/ww_xz_format.h`. liblzma first encodes a standard
XZ stream; the tool replaces its six header-magic bytes, two footer-magic bytes,
and the CRC32 selectors at offset 7 and three bytes before the stream end.
Selectors become `FF` while stored CRCs remain those of the original flags.
The decoder maps `FF` back to `01` in its private header/footer buffers before
validating those CRCs. No checksum, index, compressed data or size changes are
needed. Output remains exclusive and a failed seek/write/close removes the
incomplete file.

Packaging separately retains the compressed size and trusted expected uncompressed
size. The tool accepts any input file; it does not create or load a runtime module.
Compression parameters live in `encoder.c` and are not configurable on the command
line.

## Portable decoder boundary

Production builds expose `WaterWall::XZDecoder` separately from `ww`, backed only
by the vendored XZ Embedded decoder. Include `<ww_xz_decoder.h>` and link that
target directly. Call `wwXzDecoderInit()` once before concurrent decoder use,
then `wwXzDecode(input, input_size, output, output_capacity, expected_size)`.

The caller supplies valid non-overlapping buffers and the expected output size.
The wrapper uses `XZ_SINGLE`, so the output buffer doubles as the dictionary;
only decoder state is allocated. It requires the private CRC32 marker in both
header and footer, preserves caller input, and uses the decoder's LZMA2/x86 BCJ
support. It rejects other integrity checks and requires
`XZ_STREAM_END`, exact output size, and complete input consumption. Raw
XZ Embedded also supports LZMA2 without BCJ. The encoder always selects x86 BCJ.
A typed status distinguishes unsupported data, malformed data, allocation failure,
insufficient output space, size mismatch, and trailing data. Discard output after
any failure. There are no filesystem, Linux, mapping, or loader dependencies in
the wrapper.

`WW_PACKED_PAYLOAD_CRC32` is a CMake option, disabled by default, for the packed
launcher only. To include CRC32 calculation over the decompressed executable:

```bash
cmake --preset linux-packed -DWW_PACKED_PAYLOAD_CRC32=ON
cmake --build --preset linux-packed -j8
```

The same option applies to packed Windows builds. Stream header/footer, block
header, and index CRCs remain mandatory, as do format, size, and bounds checks.
The encoder still writes the payload CRC32; the launcher consumes its four bytes
without verifying them. Damage confined to payload data may therefore go
undetected. `WaterWall::XZDecoder` and `XZEmbedded::XZEmbedded` remain fully
checking. Only an opted-out launcher links a separate build of the same decoder
sources through `XZEmbedded::Launcher`; checked launchers reuse the ordinary
engine. Set the option back to `ON` to restore payload verification.

The native test builds a small module as an opaque input file, runs the actual
encoder, and decodes it with both the ordinary and launcher wrappers and XZ
Embedded sources used by Waterwall. Configure the `host` preset with
`-DWW_PACKED_PAYLOAD_CRC32=OFF` and `ON` to exercise both launcher policies in
Debug and Release. It also covers empty input, input spanning multiple encoder buffers,
repeatability, truncation, corruption, CRC64 rejection, unsupported BCJ filters
and offsets, concatenation/padding, output bounds, wrong expected sizes, existing
output preservation, missing input, and rejection of standard/mixed magic. The
Python test verifies that restoring magic alone is insufficient, then restores
both check selectors and uses an independent XZ decoder to verify the stream
and CRCs. Native tests reject mixed/unknown selectors, corrupted stream header/footer,
block-header and index CRCs, and CRCs calculated over unnormalized flags.
Corrupted payload CRC32 is accepted only by a launcher configured to skip it;
the decoded bytes must still match the input fixture. Truncated checks and invalid
LZMA2 control bytes are rejected with either policy. No module is loaded or executed.
