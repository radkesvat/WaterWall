#ifndef WW_MATH_H_
#define WW_MATH_H_

#include <math.h>

static inline unsigned long floor2e(unsigned long num) {
    unsigned long n = num;
    int e = 0;
    while (n>>=1) ++e;
    unsigned long ret = 1;
    while (e--) ret<<=1;
    return ret;
}

static inline unsigned long ceil2e(unsigned long num) {
    // 2**0 = 1
    if (num == 0 || num == 1)   return 1;
    unsigned long n = num - 1;
    int e = 1;
    while (n>>=1) ++e;
    unsigned long ret = 1;
    while (e--) ret<<=1;
    return ret;
}

// varint little-endian
// MSB
static inline int varintEncode(long long value, unsigned char* buf) {
    unsigned char ch;
    unsigned char *p = buf;
    int bytes = 0;
    do {
        ch = value & 0x7F;
        value >>= 7;
        *p++ = value == 0 ? ch : (ch | 0x80);
        ++bytes;
    } while (value);
    return bytes;
}

// @param[IN|OUT] len: in=>buflen, out=>varint bytesize
static inline long long varintDecode(const unsigned char* buf, int* len) {
    long long ret = 0;
    int bytes = 0, bits = 0;
    const unsigned char *p = buf;
    do {
        if (len && *len && bytes == *len) {
            // Not enough length
            *len = 0;
            return 0;
        }
        ret |= ((long long)(*p & 0x7F)) << bits;
        ++bytes;
        if ((*p & 0x80) == 0) {
            // Found end
            if (len) *len = bytes;
            return ret;
        }
        ++p;
        bits += 7;
    } while(bytes < 10);

    // Not found end
    if (len) *len = -1;
    return ret;
}



// windows defines min/max in header <stdlib.h> :)
#undef max
#undef min
#undef MAX
#undef MIN

// Waterwall requires minimum c11, so its ok to use this c11 feature

// NOLINTNEXTLINE
#define max(a, b)                                                                                                      \
    _Generic((a), unsigned long long                                                                                   \
             : maxULL, unsigned long int                                                                               \
             : maxULInt, unsigned int                                                                                  \
             : maxUInt, long long                                                                                      \
             : maxLL, signed long int                                                                                  \
             : maxSLInt, int                                                                                           \
             : maxInt, unsigned short                                                                                  \
             : maxUS, double                                                                                           \
             : maxDouble)(a, b)

static inline unsigned long long maxULL(unsigned long long a, unsigned long long b)
{
    return a > b ? a : b;
}

static inline unsigned long int maxULInt(unsigned long int a, unsigned long int b)
{
    return a > b ? a : b;
}

static inline unsigned int maxUInt(unsigned int a, unsigned int b)
{
    return a > b ? a : b;
}

static inline long long maxLL(long long a, long long b)
{
    return a > b ? a : b;
}

static inline signed long int maxSLInt(signed long int a, signed long int b)
{
    return a > b ? a : b;
}

static inline int maxInt(int a, int b)
{
    return a > b ? a : b;
}

static inline unsigned short maxUS(unsigned short a, unsigned short b)
{
    return a > b ? a : b;
}

static inline double maxDouble(double a, double b)
{
    return a > b ? a : b;
}

static inline long maxLong(long a, long b)
{
    return a > b ? a : b;
}

// NOLINTNEXTLINE
#define min(a, b)                                                                                                      \
    _Generic((a), unsigned long long                                                                                   \
             : minULL, unsigned long int                                                                               \
             : minULInt, unsigned int                                                                                  \
             : minUInt, long long                                                                                      \
             : minLL, signed long int                                                                                  \
             : minSLInt, int                                                                                           \
             : minInt, double                                                                                          \
             : minDouble)(a, b)

static inline unsigned long long minULL(unsigned long long a, unsigned long long b)
{
    return a < b ? a : b;
}

static inline unsigned long int minULInt(unsigned long int a, unsigned long int b)
{
    return a < b ? a : b;
}

static inline unsigned int minUInt(unsigned int a, unsigned int b)
{
    return a < b ? a : b;
}

static inline long long minLL(long long a, long long b)
{
    return a < b ? a : b;
}

static inline signed long int minSLInt(signed long int a, signed long int b)
{
    return a < b ? a : b;
}

static inline int minInt(int a, int b)
{
    return a < b ? a : b;
}

static inline double minDouble(double a, double b)
{
    return a < b ? a : b;
}

static inline long minLong(long a, long b)
{
    return a < b ? a : b;
}

#define ISSIGNED(t) (((t) (-1)) < ((t) 0))

#define UMAXOF(t) (((0x1ULL << ((sizeof(t) * 8ULL) - 1ULL)) - 1ULL) | (0xFULL << ((sizeof(t) * 8ULL) - 4ULL)))

#define SMAXOF(t) (((0x1ULL << ((sizeof(t) * 8ULL) - 1ULL)) - 1ULL) | (0x7ULL << ((sizeof(t) * 8ULL) - 4ULL)))

#define MAXOF(t) ((unsigned long long) (ISSIGNED(t) ? SMAXOF(t) : UMAXOF(t)))



#endif // WW_MATH_H_
