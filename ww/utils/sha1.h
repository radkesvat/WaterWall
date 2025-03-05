#ifndef WW_SHA1_H_
#define WW_SHA1_H_

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

/* for uint32_t */
#include "wlibc.h"


typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} WW_SHA1_CTX;



WW_EXPORT void wwSHA1Transform(
    uint32_t state[5],
    const unsigned char* buffer
    );

WW_EXPORT void wwSHA1Init(
    WW_SHA1_CTX * context
    );

WW_EXPORT void wwSHA1Update(
    WW_SHA1_CTX * context,
    const unsigned char *data,
    uint32_t len
    );

WW_EXPORT void wwSHA1Final(
    unsigned char digest[20],
    WW_SHA1_CTX * context
    );

WW_EXPORT void wwSHA1Pointer(
    char *hash_out,
    const char *str,
    uint32_t len);

WW_EXPORT void wwSHA1(unsigned char* input, uint32_t inputlen, unsigned char digest[20]);

// NOTE: if outputlen > 40: output[40] = '\0'
WW_EXPORT void wwSHA1Hex(unsigned char* input, uint32_t inputlen, char* output, uint32_t outputlen);



#endif // WW_SHA1_H_
