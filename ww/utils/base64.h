#ifndef WW_BASE64_H_
#define WW_BASE64_H_

#include "wlibc.h"

#define BASE64_ENCODE_OUT_SIZE(s) (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s) (((s)) / 4 * 3)

// @return encoded size
WW_EXPORT int wwBase64Encode(const unsigned char *in, unsigned int inlen, char *out);

// @return decoded size
WW_EXPORT int wwBase64Decode(const char *in, unsigned int inlen, unsigned char *out);

/* Decode canonical standard Base64, requiring padding when needed and zero pad bits.
 * Returns the decoded size, or -1 for invalid input, insufficient capacity or a size
 * above INT_MAX. Writes no terminator; invalid input may leave partial output.
 * The caller supplies inlen readable bytes and out_capacity writable bytes;
 * either pointer may be NULL only when its corresponding length is zero. */
WW_EXPORT int wwBase64DecodeCanonical(const char *in, unsigned int inlen, unsigned char *out, size_t out_capacity);

WW_EXPORT bool wwBase64UrlEncodedSizeNoPadding(size_t input_len, size_t *output_len);

WW_EXPORT bool wwBase64UrlEncodeNoPadding(const uint8_t *input, size_t input_len, char *output, size_t output_capacity,
                                          size_t *output_len);

WW_EXPORT bool wwBase64UrlDecode(const char *input, size_t input_len, uint8_t *output, size_t output_capacity,
                                 size_t *output_len);

#endif // WW_BASE64_H_
