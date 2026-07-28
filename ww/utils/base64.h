#ifndef WW_BASE64_H_
#define WW_BASE64_H_

#include "wlibc.h"

#define BASE64_ENCODE_OUT_SIZE(s) (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s) (((s)) / 4 * 3)

// @return encoded size
WW_EXPORT int wwBase64Encode(const unsigned char *in, unsigned int inlen, char *out);

// @return decoded size
WW_EXPORT int wwBase64Decode(const char *in, unsigned int inlen, unsigned char *out);

WW_EXPORT bool wwBase64UrlEncodedSizeNoPadding(size_t input_len, size_t *output_len);

WW_EXPORT bool wwBase64UrlEncodeNoPadding(const uint8_t *input, size_t input_len, char *output, size_t output_capacity,
                                          size_t *output_len);

WW_EXPORT bool wwBase64UrlDecode(const char *input, size_t input_len, uint8_t *output, size_t output_capacity,
                                 size_t *output_len);

#endif // WW_BASE64_H_
