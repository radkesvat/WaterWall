#include "ww_xz_decoder.h"
#include "ww_xz_format.h"
#include <xz.h>

void wwXzDecoderInit(void)
{
    xz_crc32_init();
}

ww_xz_result_t wwXzDecode(const void *input, size_t input_size, void *output, size_t output_capacity,
                          size_t expected_size)
{
    if (expected_size > output_capacity)
        return WW_XZ_OUTPUT_TOO_SMALL;
    if (input_size < 12)
        return WW_XZ_INVALID_DATA;

    /* Require the private CRC32 selector. The decoder normalizes its own stream
     * header/footer buffers before CRC validation; caller input stays read-only. */
    const unsigned char *bytes = input;
    if (bytes[6] != 0 || bytes[7] != WW_XZ_CRC32_MARKER)
        return WW_XZ_UNSUPPORTED;

    struct xz_dec *decoder = xz_dec_init(XZ_SINGLE, 0);
    if (decoder == NULL)
        return WW_XZ_NO_MEMORY;

    struct xz_buf buffer = {.in = input, .in_size = input_size, .out = output, .out_size = expected_size};
    enum xz_ret   result = xz_dec_run(decoder, &buffer);
    xz_dec_end(decoder);

    switch (result)
    {
    case XZ_STREAM_END:
        if (buffer.in_pos != input_size)
            return WW_XZ_TRAILING_DATA;
        return buffer.out_pos == expected_size ? WW_XZ_OK : WW_XZ_SIZE_MISMATCH;
    case XZ_MEM_ERROR:
        return WW_XZ_NO_MEMORY;
    case XZ_OPTIONS_ERROR:
    case XZ_UNSUPPORTED_CHECK:
        return WW_XZ_UNSUPPORTED;
    case XZ_BUF_ERROR:
        return WW_XZ_OUTPUT_TOO_SMALL;
    default:
        return WW_XZ_INVALID_DATA;
    }
}
