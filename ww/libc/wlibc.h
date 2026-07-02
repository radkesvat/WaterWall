#pragma once

#include "wdef.h"
#include "wmem.h"
#include "wplatform.h"

#include "wexport.h"

#include "watomic.h"
#include "wendian.h"
#include "werr.h"
#include "wfrand.h"
#include "whash.h"
#include "wmath.h"
#include "wtime.h"

#include "ww_lwip.h"

void initWLibc(void);

_Noreturn void terminateProgram(int exit_code); // in signal_manager.c
bool           isApplicationTerminating(void);  // in signal_manager.c

//--------------------Memory-------------------------------

/* STC lib will use our custom allocators (since we used custom fork (radkesvat/stc)) */
#define c_malloc(sz)               memoryAllocate((size_t) (sz))
#define c_calloc(n, sz)            memoryCalloc((size_t) (n), (size_t) (sz))
#define c_realloc(ptr, old_sz, sz) memoryReAllocate(ptr, (size_t) (sz))
#define c_free(ptr, sz)            memoryFree(ptr)

#ifdef DEBUG
static inline void debugAssertZeroBuf(void *buf, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        assert(((uint8_t *) buf)[i] == 0);
    }
}
#else

static inline void debugAssertZeroBuf(void *buf, size_t size)
{
    discard buf;
    discard size;
}

#endif

#ifndef ENABLE_MEMCOPY_AVX2
#error "ENABLE_MEMCOPY_AVX2 must be defined to either 0 or 1"
#endif

#if ENABLE_MEMCOPY_AVX512 == 1

static inline void memoryCopyAVX512(void *dest, const void *src, intmax_t n)
{
    if (n <= 0)
    {
        return;
    }

    uint8_t       *d8 = (uint8_t *) dest;
    const uint8_t *s8 = (const uint8_t *) src;

    uintptr_t dptr = (uintptr_t) d8;
    uintptr_t sptr = (uintptr_t) s8;

    size_t head = 0;
    if (((dptr ^ sptr) & 63) == 0)
    {
        size_t off = dptr & 63;
        head       = (64 - off) & 63;
    }
    else
    {
        size_t off = dptr & 63;
        head       = (64 - off) & 63;
    }
    if ((intmax_t) head > n)
    {
        head = (size_t) n;
    }

    // The prefix can be arbitrarily aligned.
    size_t t = head;
    while (t > 0)
    {
        *d8++ = *s8++;
        --t;
    }

    n -= (intmax_t) head;

    __m512i       *d_vec        = (__m512i *) d8; // dest is aligned now
    const __m512i *s_vec        = (const __m512i *) s8;
    bool           loadsAligned = (((uintptr_t) s8 & 63) == 0);

    if (n >= 64)
    {
        if (loadsAligned)
        {
            // 1024 bytes at a time (16 * 64 bytes)
            while (n >= 1024)
            {
                _mm512_store_si512(d_vec + 0, _mm512_load_si512(s_vec + 0));
                _mm512_store_si512(d_vec + 1, _mm512_load_si512(s_vec + 1));
                _mm512_store_si512(d_vec + 2, _mm512_load_si512(s_vec + 2));
                _mm512_store_si512(d_vec + 3, _mm512_load_si512(s_vec + 3));
                _mm512_store_si512(d_vec + 4, _mm512_load_si512(s_vec + 4));
                _mm512_store_si512(d_vec + 5, _mm512_load_si512(s_vec + 5));
                _mm512_store_si512(d_vec + 6, _mm512_load_si512(s_vec + 6));
                _mm512_store_si512(d_vec + 7, _mm512_load_si512(s_vec + 7));
                _mm512_store_si512(d_vec + 8, _mm512_load_si512(s_vec + 8));
                _mm512_store_si512(d_vec + 9, _mm512_load_si512(s_vec + 9));
                _mm512_store_si512(d_vec + 10, _mm512_load_si512(s_vec + 10));
                _mm512_store_si512(d_vec + 11, _mm512_load_si512(s_vec + 11));
                _mm512_store_si512(d_vec + 12, _mm512_load_si512(s_vec + 12));
                _mm512_store_si512(d_vec + 13, _mm512_load_si512(s_vec + 13));
                _mm512_store_si512(d_vec + 14, _mm512_load_si512(s_vec + 14));
                _mm512_store_si512(d_vec + 15, _mm512_load_si512(s_vec + 15));
                d_vec += 16;
                s_vec += 16;
                n -= 1024;
            }

            // 256 bytes at a time (4 * 64 bytes)
            while (n >= 256)
            {
                _mm512_store_si512(d_vec + 0, _mm512_load_si512(s_vec + 0));
                _mm512_store_si512(d_vec + 1, _mm512_load_si512(s_vec + 1));
                _mm512_store_si512(d_vec + 2, _mm512_load_si512(s_vec + 2));
                _mm512_store_si512(d_vec + 3, _mm512_load_si512(s_vec + 3));
                d_vec += 4;
                s_vec += 4;
                n -= 256;
            }

            // 128 bytes at a time (2 * 64 bytes)
            while (n >= 128)
            {
                _mm512_store_si512(d_vec + 0, _mm512_load_si512(s_vec + 0));
                _mm512_store_si512(d_vec + 1, _mm512_load_si512(s_vec + 1));
                d_vec += 2;
                s_vec += 2;
                n -= 128;
            }

            // 64 bytes at a time
            while (n >= 64)
            {
                _mm512_store_si512(d_vec + 0, _mm512_load_si512(s_vec + 0));
                d_vec += 1;
                s_vec += 1;
                n -= 64;
            }
        }
        else
        {
            // Unaligned loads, aligned stores
            while (n >= 1024)
            {
                _mm512_store_si512(d_vec + 0, _mm512_loadu_si512(s_vec + 0));
                _mm512_store_si512(d_vec + 1, _mm512_loadu_si512(s_vec + 1));
                _mm512_store_si512(d_vec + 2, _mm512_loadu_si512(s_vec + 2));
                _mm512_store_si512(d_vec + 3, _mm512_loadu_si512(s_vec + 3));
                _mm512_store_si512(d_vec + 4, _mm512_loadu_si512(s_vec + 4));
                _mm512_store_si512(d_vec + 5, _mm512_loadu_si512(s_vec + 5));
                _mm512_store_si512(d_vec + 6, _mm512_loadu_si512(s_vec + 6));
                _mm512_store_si512(d_vec + 7, _mm512_loadu_si512(s_vec + 7));
                _mm512_store_si512(d_vec + 8, _mm512_loadu_si512(s_vec + 8));
                _mm512_store_si512(d_vec + 9, _mm512_loadu_si512(s_vec + 9));
                _mm512_store_si512(d_vec + 10, _mm512_loadu_si512(s_vec + 10));
                _mm512_store_si512(d_vec + 11, _mm512_loadu_si512(s_vec + 11));
                _mm512_store_si512(d_vec + 12, _mm512_loadu_si512(s_vec + 12));
                _mm512_store_si512(d_vec + 13, _mm512_loadu_si512(s_vec + 13));
                _mm512_store_si512(d_vec + 14, _mm512_loadu_si512(s_vec + 14));
                _mm512_store_si512(d_vec + 15, _mm512_loadu_si512(s_vec + 15));
                d_vec += 16;
                s_vec += 16;
                n -= 1024;
            }

            while (n >= 256)
            {
                _mm512_store_si512(d_vec + 0, _mm512_loadu_si512(s_vec + 0));
                _mm512_store_si512(d_vec + 1, _mm512_loadu_si512(s_vec + 1));
                _mm512_store_si512(d_vec + 2, _mm512_loadu_si512(s_vec + 2));
                _mm512_store_si512(d_vec + 3, _mm512_loadu_si512(s_vec + 3));
                d_vec += 4;
                s_vec += 4;
                n -= 256;
            }

            while (n >= 128)
            {
                _mm512_store_si512(d_vec + 0, _mm512_loadu_si512(s_vec + 0));
                _mm512_store_si512(d_vec + 1, _mm512_loadu_si512(s_vec + 1));
                d_vec += 2;
                s_vec += 2;
                n -= 128;
            }

            while (n >= 64)
            {
                _mm512_store_si512(d_vec + 0, _mm512_loadu_si512(s_vec + 0));
                d_vec += 1;
                s_vec += 1;
                n -= 64;
            }
        }
    }

    // Tail
    if (n > 0)
    {
        d8 = (uint8_t *) d_vec;
        s8 = (const uint8_t *) s_vec;

        if ((((uintptr_t) d8 | (uintptr_t) s8) & 7) == 0)
        {
            while (n >= 8)
            {
                *(uint64_t *) d8 = *(const uint64_t *) s8;
                d8 += 8;
                s8 += 8;
                n -= 8;
            }
        }
        while (n--)
        {
            *d8++ = *s8++;
        }
    }
}

#define memoryCopyLarge memoryCopyAVX512

#elif ENABLE_MEMCOPY_AVX2 == 1

static inline void memoryCopyAVX2(void *dest, const void *src, intmax_t n)
{

    if (n <= 0)
    {
        return;
    }

    uint8_t       *d8 = (uint8_t *) dest;
    const uint8_t *s8 = (const uint8_t *) src;

    uintptr_t dptr = (uintptr_t) d8;
    uintptr_t sptr = (uintptr_t) s8;

    // align both if possible, else align dest only
    size_t head = 0;
    if (((dptr ^ sptr) & 31) == 0)
    {
        size_t off = dptr & 31;
        head       = (32 - off) & 31;
    }
    else
    {
        size_t off = dptr & 31;
        head       = (32 - off) & 31;
    }
    if ((intmax_t) head > n)
    {
        head = (size_t) n;
    }

    // The prefix can be arbitrarily aligned.
    size_t t = head;
    while (t > 0)
    {
        *d8++ = *s8++;
        --t;
    }

    n -= (intmax_t) head;

    __m256i       *d_vec      = (__m256i *) d8; // dest is aligned now
    const __m256i *s_vec      = (const __m256i *) s8;
    bool           is_aligned = (((uintptr_t) s8 & 31) == 0);

    if (n >= 32)
    {
        if (is_aligned)
        {
            // 512B blocks (16x32B)
            while (n >= 512)
            {
                _mm256_store_si256(d_vec + 0, _mm256_load_si256(s_vec + 0));
                _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vec + 1));
                _mm256_store_si256(d_vec + 2, _mm256_load_si256(s_vec + 2));
                _mm256_store_si256(d_vec + 3, _mm256_load_si256(s_vec + 3));
                _mm256_store_si256(d_vec + 4, _mm256_load_si256(s_vec + 4));
                _mm256_store_si256(d_vec + 5, _mm256_load_si256(s_vec + 5));
                _mm256_store_si256(d_vec + 6, _mm256_load_si256(s_vec + 6));
                _mm256_store_si256(d_vec + 7, _mm256_load_si256(s_vec + 7));
                _mm256_store_si256(d_vec + 8, _mm256_load_si256(s_vec + 8));
                _mm256_store_si256(d_vec + 9, _mm256_load_si256(s_vec + 9));
                _mm256_store_si256(d_vec + 10, _mm256_load_si256(s_vec + 10));
                _mm256_store_si256(d_vec + 11, _mm256_load_si256(s_vec + 11));
                _mm256_store_si256(d_vec + 12, _mm256_load_si256(s_vec + 12));
                _mm256_store_si256(d_vec + 13, _mm256_load_si256(s_vec + 13));
                _mm256_store_si256(d_vec + 14, _mm256_load_si256(s_vec + 14));
                _mm256_store_si256(d_vec + 15, _mm256_load_si256(s_vec + 15));
                d_vec += 16;
                s_vec += 16;
                n -= 512;
            }
            // 128B blocks (4x32B)
            while (n >= 128)
            {
                _mm256_store_si256(d_vec + 0, _mm256_load_si256(s_vec + 0));
                _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vec + 1));
                _mm256_store_si256(d_vec + 2, _mm256_load_si256(s_vec + 2));
                _mm256_store_si256(d_vec + 3, _mm256_load_si256(s_vec + 3));
                d_vec += 4;
                s_vec += 4;
                n -= 128;
            }
            // 64B blocks (2x32B)
            while (n >= 64)
            {
                _mm256_store_si256(d_vec + 0, _mm256_load_si256(s_vec + 0));
                _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vec + 1));
                d_vec += 2;
                s_vec += 2;
                n -= 64;
            }
            // 32B
            while (n >= 32)
            {
                _mm256_store_si256(d_vec + 0, _mm256_load_si256(s_vec + 0));
                d_vec += 1;
                s_vec += 1;
                n -= 32;
            }
        }
        else
        {
            // Unaligned loads, aligned stores
            while (n >= 512)
            {
                _mm256_store_si256(d_vec + 0, _mm256_loadu_si256(s_vec + 0));
                _mm256_store_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
                _mm256_store_si256(d_vec + 2, _mm256_loadu_si256(s_vec + 2));
                _mm256_store_si256(d_vec + 3, _mm256_loadu_si256(s_vec + 3));
                _mm256_store_si256(d_vec + 4, _mm256_loadu_si256(s_vec + 4));
                _mm256_store_si256(d_vec + 5, _mm256_loadu_si256(s_vec + 5));
                _mm256_store_si256(d_vec + 6, _mm256_loadu_si256(s_vec + 6));
                _mm256_store_si256(d_vec + 7, _mm256_loadu_si256(s_vec + 7));
                _mm256_store_si256(d_vec + 8, _mm256_loadu_si256(s_vec + 8));
                _mm256_store_si256(d_vec + 9, _mm256_loadu_si256(s_vec + 9));
                _mm256_store_si256(d_vec + 10, _mm256_loadu_si256(s_vec + 10));
                _mm256_store_si256(d_vec + 11, _mm256_loadu_si256(s_vec + 11));
                _mm256_store_si256(d_vec + 12, _mm256_loadu_si256(s_vec + 12));
                _mm256_store_si256(d_vec + 13, _mm256_loadu_si256(s_vec + 13));
                _mm256_store_si256(d_vec + 14, _mm256_loadu_si256(s_vec + 14));
                _mm256_store_si256(d_vec + 15, _mm256_loadu_si256(s_vec + 15));
                d_vec += 16;
                s_vec += 16;
                n -= 512;
            }
            while (n >= 128)
            {
                _mm256_store_si256(d_vec + 0, _mm256_loadu_si256(s_vec + 0));
                _mm256_store_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
                _mm256_store_si256(d_vec + 2, _mm256_loadu_si256(s_vec + 2));
                _mm256_store_si256(d_vec + 3, _mm256_loadu_si256(s_vec + 3));
                d_vec += 4;
                s_vec += 4;
                n -= 128;
            }
            while (n >= 64)
            {
                _mm256_store_si256(d_vec + 0, _mm256_loadu_si256(s_vec + 0));
                _mm256_store_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
                d_vec += 2;
                s_vec += 2;
                n -= 64;
            }
            while (n >= 32)
            {
                _mm256_store_si256(d_vec + 0, _mm256_loadu_si256(s_vec + 0));
                d_vec += 1;
                s_vec += 1;
                n -= 32;
            }
        }
    }

    // Tail
    if (n > 0)
    {
        d8 = (uint8_t *) d_vec;
        s8 = (const uint8_t *) s_vec;

        if ((((uintptr_t) d8 | (uintptr_t) s8) & 7) == 0)
        {
            while (n >= 8)
            {
                *(uint64_t *) d8 = *(const uint64_t *) s8;
                d8 += 8;
                s8 += 8;
                n -= 8;
            }
        }
        while (n--)
        {
            *d8++ = *s8++;
        }
    }
}

#define memoryCopyLarge memoryCopyAVX2

#else

#define memoryCopyLarge memoryCopy

#endif

#if ENABLE_MEMCOPY_AVX2 == 1 || ENABLE_MEMCOPY_AVX512 == 1

// n is in bytes
static inline void memoryZeroAligned32(void *ptr, size_t n)
{
    assert(ptr != NULL);
    assert((((uintptr_t) ptr) & 31U) == 0);
    assert((n & 31U) == 0);

    n = ALIGN2(n, 32);

    __m256i      *vec  = (__m256i *) ptr;
    const __m256i zero = _mm256_setzero_si256();

    for (size_t i = 0; i < n / 32; i++)
    {
        _mm256_store_si256(&vec[i], zero);
    }
}

#else
// n is in bytes
static inline void memoryZeroAligned32(void *ptr, size_t n)
{
    assert(ptr != NULL);
    assert((((uintptr_t) ptr) & 31U) == 0);
    assert((n & 31U) == 0);

    n = ALIGN2(n, 32);

    uintmax_t *cur = ptr;
    size_t     i;
    for (i = 0; i < n / sizeof(uintmax_t); i++)
    {
        cur[i] = 0;
    }

    uint8_t *cur2 = (uint8_t *) &(cur[i]);
    for (size_t j = 0; j < n % sizeof(uintmax_t); j++)
    {
        cur2[j] = 0;
    }
}

#endif

// n is in bytes
static inline int memoryCompareAligned32(const void *a, const void *b, size_t n)
{
    assert(a != NULL);
    assert(b != NULL);
    assert((((uintptr_t) a) & 31U) == 0);
    assert((((uintptr_t) b) & 31U) == 0);
    assert((n & 31U) == 0);

    return memoryCompare(a, b, n);
}

// n is in bytes
static inline bool memoryEqualAligned32(const void *a, const void *b, size_t n)
{
    return memoryCompareAligned32(a, b, n) == 0;
}

// same as memoryCopyLarge, but defines the symbol for the linker, used for extranl libraries that dont want to include
// this file, use the 'memoryCopyLarge' above for your use
void wwMemoryCopyLarge(void *dest, const void *src, intmax_t n);

//--------------------string-------------------------------

#ifndef STRINGIFY
#define STRINGIFY(x) #x
#endif
#define TOSTRING(x) STRINGIFY(x)

WW_EXPORT char *stringUpperCase(char *str);
WW_EXPORT char *stringLowerCase(char *str);
WW_EXPORT char *stringReverse(char *str);
char           *stringDuplicate(const char *src);
char           *stringConcat(const char *s1, const char *s2);

static inline bool stringStartsWith(const char *str, const char *start)
{
    assert(str != NULL && start != NULL);
    while (*str && *start && *str == *start)
    {
        ++str;
        ++start;
    }
    return *start == '\0';
}

static inline bool stringEndsWith(const char *str, const char *end)
{
    assert(str != NULL && end != NULL);
    size_t str_len = stringLength(str);
    size_t end_len = stringLength(end);

    if (str_len < end_len)
    {
        return false;
    }
    return memoryCompare(str + str_len - end_len, end, end_len) == 0;
}

static inline bool stringContains(const char *str, const char *sub)
{
    assert(str != NULL && sub != NULL);
    return strstr(str, sub) != NULL;
}
WW_EXPORT bool stringWildCardMatch(const char *str, const char *pattern);

WW_EXPORT char *stringNewWithoutSpace(const char *str);

// #if HAVE_STRLCPY

// #define stringCopyN strlcpy

// #else

// strncpy n = sizeof(dest_buf)-1
// stringCopyN n = sizeof(dest_buf)
WW_EXPORT char *stringCopyN(char *dest, const char *src, size_t n);

// #endif

#if HAVE_STRLCAT

#define stringCat strlcat

#else

// strncat n = sizeof(dest_buf)-1-stringLength(dest)
// stringCopyN n = sizeof(dest_buf)
WW_EXPORT char *stringCat(char *dest, const char *src, size_t n);

#endif

#define stringChr strchr

static inline char *stringChrLen(const char *s, char c, size_t n)
{
    assert(s != NULL);
    const char *p = s;
    while (*p != '\0' && n-- > 0)
    {
        if (*p == c)
        {
            return (char *) p;
        }
        ++p;
    }
    return NULL;
}

#define stringChrDot(str) strrchr(str, '.')

#define stringCopy strcpy

static inline uint8_t asciiLower(uint8_t c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return (uint8_t) (c | 0x20U);
    }
    return c;
}

static inline uint8_t asciiUpper(uint8_t c)
{
    if (c >= 'a' && c <= 'z')
    {
        return (uint8_t) (c & ~0x20U);
    }
    return c;
}

static inline bool asciiIsAlpha(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static inline bool asciiCaseEqual(uint8_t a, uint8_t b)
{
    return asciiLower(a) == asciiLower(b);
}

static inline bool stringStartsWithIgnoreCase(const char *str, const char *start)
{
    assert(str != NULL && start != NULL);
    while (*start != '\0')
    {
        if (*str == '\0' || ! asciiCaseEqual((uint8_t) *str, (uint8_t) *start))
        {
            return false;
        }
        ++str;
        ++start;
    }
    return true;
}

static inline int asciiHexValue(uint8_t c)
{
    if (c >= '0' && c <= '9')
    {
        return (int) (c - '0');
    }

    c = asciiLower(c);
    if (c >= 'a' && c <= 'f')
    {
        return (int) (c - 'a' + 10);
    }

    return -1;
}

static inline uint8_t asciiHexDigitLower(uint8_t value)
{
    assert(value < 16U);
    return (uint8_t) (value < 10U ? '0' + value : 'a' + value - 10U);
}

static inline bool asciiHexDecodeByte(uint8_t hi, uint8_t lo, uint8_t *out)
{
    int hi_value = asciiHexValue(hi);
    int lo_value = asciiHexValue(lo);
    if (hi_value < 0 || lo_value < 0)
    {
        return false;
    }

    *out = (uint8_t) ((hi_value << 4U) | lo_value);
    return true;
}

static inline bool asciiHexDecodeBytes(const uint8_t *hex, size_t hex_len, uint8_t *out, size_t out_len)
{
    if (out_len > SIZE_MAX / 2U || hex_len != out_len * 2U)
    {
        return false;
    }

    for (size_t i = 0; i < out_len; ++i)
    {
        if (! asciiHexDecodeByte(hex[i * 2U], hex[i * 2U + 1U], &out[i]))
        {
            return false;
        }
    }

    return true;
}

static inline void asciiHexEncodeBytesLower(const uint8_t *bytes, size_t bytes_len, uint8_t *out)
{
    for (size_t i = 0; i < bytes_len; ++i)
    {
        out[i * 2U]      = asciiHexDigitLower((uint8_t) ((bytes[i] >> 4U) & 0x0FU));
        out[i * 2U + 1U] = asciiHexDigitLower((uint8_t) (bytes[i] & 0x0FU));
    }
}

static inline bool asciiHexNormalizeLower(const uint8_t *hex, size_t hex_len, uint8_t *out)
{
    for (size_t i = 0; i < hex_len; ++i)
    {
        int value = asciiHexValue(hex[i]);
        if (value < 0)
        {
            return false;
        }

        out[i] = asciiHexDigitLower((uint8_t) value);
    }

    return true;
}

static inline bool stringAsciiCaseEquals(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
    {
        return false;
    }

    while (*a != '\0' && *b != '\0')
    {
        if (! asciiCaseEqual((uint8_t) *a, (uint8_t) *b))
        {
            return false;
        }
        ++a;
        ++b;
    }

    return *a == '\0' && *b == '\0';
}

static inline bool stringAsciiCaseContains(const char *haystack, const char *needle)
{
    if (haystack == NULL || needle == NULL || *needle == '\0')
    {
        return false;
    }

    size_t needle_len = stringLength(needle);
    size_t hay_len    = stringLength(haystack);

    if (needle_len > hay_len)
    {
        return false;
    }

    for (size_t i = 0; i <= hay_len - needle_len; ++i)
    {
        bool match = true;
        for (size_t j = 0; j < needle_len; ++j)
        {
            if (! asciiCaseEqual((uint8_t) haystack[i + j], (uint8_t) needle[j]))
            {
                match = false;
                break;
            }
        }

        if (match)
        {
            return true;
        }
    }

    return false;
}

static inline bool stringAsciiCaseContainsToken(const char *value, const char *token)
{
    if (value == NULL || token == NULL || *token == '\0')
    {
        return false;
    }

    size_t      token_len = stringLength(token);
    const char *p         = value;
    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t' || *p == ',')
        {
            ++p;
        }

        if (*p == '\0')
        {
            break;
        }

        const char *end = p;
        while (*end != '\0' && *end != ',')
        {
            ++end;
        }

        const char *tail = end;
        while (tail > p && (tail[-1] == ' ' || tail[-1] == '\t'))
        {
            --tail;
        }

        size_t part_len = (size_t) (tail - p);
        if (part_len == token_len)
        {
            bool match = true;
            for (size_t i = 0; i < part_len; ++i)
            {
                if (! asciiCaseEqual((uint8_t) p[i], (uint8_t) token[i]))
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return true;
            }
        }

        p = end;
    }

    return false;
}

static inline bool stringFormatFits(int written, size_t buf_len)
{
    return written > 0 && (size_t) written < buf_len;
}

//--------------------file-------------------------------

static inline bool filePathIsSeparator(char ch)
{
#ifdef OS_WIN
    return ch == '/' || ch == '\\';
#else
    return ch == '/';
#endif
}

static inline char *stringChrDir(const char *filepath)
{
    const char *p = filepath + stringLength(filepath);
    while (p > filepath)
    {
        --p;
        if (filePathIsSeparator(*p))
        {
            return (char *) p;
        }
    }
    return NULL;
}

char *readFile(const char *path);
bool  writeFile(const char *path, const char *data, size_t len);

// basename
static inline const char *filePathBaseName(const char *filepath)
{
    const char *pos = stringChrDir(filepath);
    return pos ? pos + 1 : filepath;
}

static inline const char *filePathSuffixName(const char *filename)
{
    const char *pos = stringChrDot(filename);
    return pos ? pos + 1 : "";
}
// mkdir -p
WW_EXPORT int createDirIfNotExists(const char *dir);
// wwRmDir -p
WW_EXPORT int removeDirIfExists(const char *dir);
// path
WW_EXPORT bool   dirExists(const char *path);
WW_EXPORT bool   isDir(const char *path);
WW_EXPORT bool   isFile(const char *path);
WW_EXPORT bool   isLink(const char *path);
WW_EXPORT size_t getFileSize(const char *filepath);

WW_EXPORT char *getExecuteablePath(char *buf, int size);
WW_EXPORT char *getExecuteableDir(char *buf, int size);
WW_EXPORT char *getExecuteableFile(char *buf, int size);
WW_EXPORT char *getRunDir(char *buf, int size);

// random
WW_EXPORT int   randomRange(int min, int max);
WW_EXPORT char *randomString(char *buf, int len);

// 1 y on yes true enable => true
WW_EXPORT bool stringRepresenstsTrue(const char *str);
// 1T2G3M4K5B => ?B
WW_EXPORT size_t stringToSize(const char *str);
// 1w2d3h4m5s => ?s
WW_EXPORT time_t stringToTime(const char *str);

// scheme:[//[user[:password]@]host[:port]][/path][?query][#fragment]
typedef enum
{
    WW_URL_SCHEME,
    WW_URL_USERNAME,
    WW_URL_PASSWORD,
    WW_URL_HOST,
    WW_URL_PORT,
    WW_URL_PATH,
    WW_URL_QUERY,
    WW_URL_FRAGMENT,
    WW_URL_FIELD_NUM,
} hurl_field_e;

typedef struct hurl_s
{
    struct
    {
        unsigned short off;
        unsigned short len;
    } fields[WW_URL_FIELD_NUM];
    unsigned short port;
} hurl_t;

WW_EXPORT int stringToUrl(hurl_t *stURL, const char *strURL);

//-------------------------prints----------------------------------
// #define printError perror

static void printDebug(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fflush(stdout);
}

static void printError(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fflush(stderr);
}

static void printHex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
    fflush(stdout);
}

static void printASCII(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] >= 32 && data[i] < 127)
        {
            printf("%c", data[i]);
        }
        else
        {
            printf("?");
        }
    }
    printf("\n");
    fflush(stdout);
}
