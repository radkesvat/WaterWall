#ifndef WW_MATH_H_
#define WW_MATH_H_

#include <math.h>
#include <stdint.h>
#include <stddef.h>

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
    int bytes = 0;
    int bits = 0;
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

// Waterwall requires minimum C11. Use _Generic for type-safe min/max without double-evaluating args.

// Helpers for integral min/max (evaluate once)
#define WW_DEFINE_MINMAX_INTEGRAL(T, name, Name)                     \
    static inline T wwMin##Name(T a, T b) { return a < b ? a : b; }  \
    static inline T wwMax##Name(T a, T b) { return a > b ? a : b; }

WW_DEFINE_MINMAX_INTEGRAL(signed char, schar, Schar)
WW_DEFINE_MINMAX_INTEGRAL(unsigned char, uchar, Uchar)
WW_DEFINE_MINMAX_INTEGRAL(char, char, Char)
WW_DEFINE_MINMAX_INTEGRAL(short, short, Short)
WW_DEFINE_MINMAX_INTEGRAL(unsigned short, ushort, Ushort)
WW_DEFINE_MINMAX_INTEGRAL(int, int, Int)
WW_DEFINE_MINMAX_INTEGRAL(unsigned int, uint, Uint)
WW_DEFINE_MINMAX_INTEGRAL(long, long, Long)
WW_DEFINE_MINMAX_INTEGRAL(unsigned long, ulong, Ulong)
WW_DEFINE_MINMAX_INTEGRAL(long long, llong, Llong)
WW_DEFINE_MINMAX_INTEGRAL(unsigned long long, ullong, Ullong)

// Floating-point: use fmin*/fmax* to handle NaNs per IEEE-754 semantics
static inline float wwMinFloat(float a, float b) { return fminf(a, b); }
static inline float wwMaxFloat(float a, float b) { return fmaxf(a, b); }
static inline double wwMinDouble(double a, double b) { return fmin(a, b); }
static inline double wwMaxDouble(double a, double b) { return fmax(a, b); }
static inline long double wwMinLDouble(long double a, long double b) { return fminl(a, b); }
static inline long double wwMaxLDouble(long double a, long double b) { return fmaxl(a, b); }

// NOLINTNEXTLINE: generic min/max selection based on the type of the first arg
#define max(a, b)                                                                                                      \
    _Generic((a),                                                                                                      \
             signed char: wwMaxSchar,                                                                                  \
             unsigned char: wwMaxUchar,                                                                                \
             char: wwMaxChar,                                                                                          \
             short: wwMaxShort,                                                                                        \
             unsigned short: wwMaxUshort,                                                                              \
             int: wwMaxInt,                                                                                            \
             unsigned int: wwMaxUint,                                                                                  \
             long: wwMaxLong,                                                                                          \
             unsigned long: wwMaxUlong,                                                                                \
             long long: wwMaxLlong,                                                                                    \
             unsigned long long: wwMaxUllong,                                                                          \
             float: wwMaxFloat,                                                                                        \
             double: wwMaxDouble,                                                                                      \
             long double: wwMaxLDouble)(a, b)

// NOLINTNEXTLINE: generic min selection based on the type of the first arg
#define min(a, b)                                                                                                      \
    _Generic((a),                                                                                                      \
             signed char: wwMinSchar,                                                                                  \
             unsigned char: wwMinUchar,                                                                                \
             char: wwMinChar,                                                                                          \
             short: wwMinShort,                                                                                        \
             unsigned short: wwMinUshort,                                                                              \
             int: wwMinInt,                                                                                            \
             unsigned int: wwMinUint,                                                                                  \
             long: wwMinLong,                                                                                          \
             unsigned long: wwMinUlong,                                                                                \
             long long: wwMinLlong,                                                                                    \
             unsigned long long: wwMinUllong,                                                                          \
             float: wwMinFloat,                                                                                        \
             double: wwMinDouble,                                                                                      \
             long double: wwMinLDouble)(a, b)

// Convenience typed helpers for fixed-width ints and common size types. These cast first,
// so mixed-type calls are safe and predictable.
#define MAX_U8(a, b)  max((uint8_t)(a), (uint8_t)(b))
#define MIN_U8(a, b)  min((uint8_t)(a), (uint8_t)(b))
#define MAX_U16(a, b) max((uint16_t)(a), (uint16_t)(b))
#define MIN_U16(a, b) min((uint16_t)(a), (uint16_t)(b))
#define MAX_U32(a, b) max((uint32_t)(a), (uint32_t)(b))
#define MIN_U32(a, b) min((uint32_t)(a), (uint32_t)(b))
#define MAX_U64(a, b) max((uint64_t)(a), (uint64_t)(b))
#define MIN_U64(a, b) min((uint64_t)(a), (uint64_t)(b))
#define MAX_I8(a, b)  max((int8_t)(a), (int8_t)(b))
#define MIN_I8(a, b)  min((int8_t)(a), (int8_t)(b))
#define MAX_I16(a, b) max((int16_t)(a), (int16_t)(b))
#define MIN_I16(a, b) min((int16_t)(a), (int16_t)(b))
#define MAX_I32(a, b) max((int32_t)(a), (int32_t)(b))
#define MIN_I32(a, b) min((int32_t)(a), (int32_t)(b))
#define MAX_I64(a, b) max((int64_t)(a), (int64_t)(b))
#define MIN_I64(a, b) min((int64_t)(a), (int64_t)(b))
#define MAX_SIZE(a, b) max((size_t)(a), (size_t)(b))
#define MIN_SIZE(a, b) min((size_t)(a), (size_t)(b))
#define MAX_PTRDIFF(a, b) max((ptrdiff_t)(a), (ptrdiff_t)(b))
#define MIN_PTRDIFF(a, b) min((ptrdiff_t)(a), (ptrdiff_t)(b))

#define ISSIGNED(t) (((t) (-1)) < ((t) 0))

#define UMAXOF(t) (((0x1ULL << ((sizeof(t) * 8ULL) - 1ULL)) - 1ULL) | (0xFULL << ((sizeof(t) * 8ULL) - 4ULL)))

#define SMAXOF(t) (((0x1ULL << ((sizeof(t) * 8ULL) - 1ULL)) - 1ULL) | (0x7ULL << ((sizeof(t) * 8ULL) - 4ULL)))

#define MAXOF(t) ((unsigned long long) (ISSIGNED(t) ? SMAXOF(t) : UMAXOF(t)))



#endif // WW_MATH_H_
