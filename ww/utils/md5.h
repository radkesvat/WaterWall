#ifndef HV_MD5_H_
#define HV_MD5_H_

#include "hexport.h"

typedef struct {
    unsigned int    count[2];
    unsigned int    state[4];
    unsigned char   buffer[64];
} HV_MD5_CTX;

BEGIN_EXTERN_C

HV_EXPORT void wwMD5Init(HV_MD5_CTX *ctx);
HV_EXPORT void wwMD5Update(HV_MD5_CTX *ctx, unsigned char *input, unsigned int inputlen);
HV_EXPORT void wwMD5Final(HV_MD5_CTX *ctx, unsigned char digest[16]);

HV_EXPORT void wwMD5(unsigned char* input, unsigned int inputlen, unsigned char digest[16]);

// NOTE: if outputlen > 32: output[32] = '\0'
HV_EXPORT void wwM5Hex(unsigned char* input, unsigned int inputlen, char* output, unsigned int outputlen);

END_EXTERN_C

#endif // HV_MD5_H_
