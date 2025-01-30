#ifndef WW_MD5_H_
#define WW_MD5_H_

#include "wlibc.h"

typedef struct {
    unsigned int    count[2];
    unsigned int    state[4];
    unsigned char   buffer[64];
} ww_md5_ctx_t;

WW_EXPORT void wwMD5Init(ww_md5_ctx_t *ctx);
WW_EXPORT void wwMD5Update(ww_md5_ctx_t *ctx, unsigned char *input, unsigned int inputlen);
WW_EXPORT void wwMD5Final(ww_md5_ctx_t *ctx, unsigned char digest[16]);

WW_EXPORT void wwMD5(unsigned char* input, unsigned int inputlen, unsigned char digest[16]);

// NOTE: if outputlen > 32: output[32] = '\0'
WW_EXPORT void wwMD5Hex(unsigned char* input, unsigned int inputlen, char* output, unsigned int outputlen);

#endif // WW_MD5_H_
