

#include <openssl/base.h>

#include <openssl/ssl.h>

#include <cstdint>

#include "brotli/decode.h"

extern "C" {
    int tlsclientDecompressBrotliCert(SSL *ssl, CRYPTO_BUFFER **out, size_t uncompressed_len, const uint8_t *in,
                                  size_t in_len);
}



int tlsclientDecompressBrotliCert(SSL *ssl, CRYPTO_BUFFER **out, size_t uncompressed_len, const uint8_t *in,
                                  size_t in_len)
{
    uint8_t                       *data;
    bssl::UniquePtr<CRYPTO_BUFFER> decompressed(CRYPTO_BUFFER_alloc(&data, uncompressed_len));
    if (! decompressed)
    {
        return 0;
    }

    size_t output_size = uncompressed_len;
    if (BrotliDecoderDecompress(in_len, in, &output_size, data) != BROTLI_DECODER_RESULT_SUCCESS ||
        output_size != uncompressed_len)
    {
        return 0;
    }

    *out = decompressed.release();
    return 1;
}
