#ifndef WW_XZ_DECODER_H
#define WW_XZ_DECODER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum ww_xz_result
    {
        WW_XZ_OK,
        WW_XZ_INVALID_DATA,
        WW_XZ_UNSUPPORTED,
        WW_XZ_NO_MEMORY,
        WW_XZ_OUTPUT_TOO_SMALL,
        WW_XZ_SIZE_MISMATCH,
        WW_XZ_TRAILING_DATA
    } ww_xz_result_t;

    /* Call once before decoding or starting decoder threads. This initializes the
     * upstream CRC32 table and must not race with any XZ Embedded CRC32 use. */
    void wwXzDecoderInit(void);

    /* Decode one Waterwall stream with private magic and CRC32 selector using XZ_SINGLE.
     * input/output must be non-null, non-overlapping buffers of the supplied sizes.
     * Input is never modified, including during stream-flag normalization.
     * expected_size is trusted caller metadata and may be zero. Success requires
     * exactly expected_size output bytes and complete input consumption. No stream
     * padding or concatenation is accepted. Output is unspecified on failure.
     * Each call owns its decoder state; no separate dictionary is allocated. */
    ww_xz_result_t wwXzDecode(const void *input, size_t input_size, void *output, size_t output_capacity,
                              size_t expected_size);

#ifdef __cplusplus
}
#endif
#endif
