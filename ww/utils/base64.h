#ifndef WW_BASE64_H_
#define WW_BASE64_H_

#include "wexport.h"

#define BASE64_ENCODE_OUT_SIZE(s)   (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s)   (((s)) / 4 * 3)



// @return encoded size
WW_EXPORT int wwBase64Encode(const unsigned char *in, unsigned int inlen, char *out);

// @return decoded size
WW_EXPORT int wwBase64Decode(const char *in, unsigned int inlen, unsigned char *out);




#endif // WW_BASE64_H_
