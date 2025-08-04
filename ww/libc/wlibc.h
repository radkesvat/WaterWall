#pragma once

#include "wplatform.h"

#include "wdef.h"

#include "watomic.h"
#include "wchecksum.h"
#include "wendian.h"
#include "werr.h"
#include "wexport.h"
#include "wfrand.h"
#include "whash.h"
#include "wmath.h"
#include "wmutex.h"
#include "wtime.h"

#include "ww_lwip.h"

void initWLibc(void);

//--------------------Memory-------------------------------

struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

_Noreturn void terminateProgram(int exit_code); // in signal_manager.c

void *memoryAllocate(size_t size);
void *memoryAllocateZero(size_t size);
void *memoryReAllocate(void *ptr, size_t size);
void  memoryFree(void *ptr);

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size);
void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size);
void  memoryDedicatedFree(dedicated_memory_t *dm, void *ptr);

/* STC lib will use our custom allocators*/
#define c_malloc(sz)               memoryAllocate((size_t) (sz))
#define c_calloc(n, sz)            memoryAllocateZero((size_t) ((n) * (sz)))
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

#include <x86intrin.h>
static inline void memoryCopyAVX512(void *dest, const void *src, intmax_t n)
{
    __m512i       *d_vec = (__m512i *) (dest);
    const __m512i *s_vec = (const __m512i *) (src);

    bool aligned = ((uintptr_t) dest % 64 == 0 && (uintptr_t) src % 64 == 0);

    if (aligned)
    {
        // Copy 1024 bytes at a time (16 * 64 bytes)
        while (n >= 1024)
        {
            _mm512_store_si512(d_vec, _mm512_load_si512(s_vec));
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
            n -= 1024;
            d_vec += 16;
            s_vec += 16;
        }

        // Copy 256 bytes at a time (4 * 64 bytes)
        while (n >= 256)
        {
            _mm512_store_si512(d_vec, _mm512_load_si512(s_vec));
            _mm512_store_si512(d_vec + 1, _mm512_load_si512(s_vec + 1));
            _mm512_store_si512(d_vec + 2, _mm512_load_si512(s_vec + 2));
            _mm512_store_si512(d_vec + 3, _mm512_load_si512(s_vec + 3));
            n -= 256;
            d_vec += 4;
            s_vec += 4;
        }

        // Copy 128 bytes at a time (2 * 64 bytes)
        while (n >= 128)
        {
            _mm512_store_si512(d_vec, _mm512_load_si512(s_vec));
            _mm512_store_si512(d_vec + 1, _mm512_load_si512(s_vec + 1));
            n -= 128;
            d_vec += 2;
            s_vec += 2;
        }

        // Copy 64 bytes at a time
        while (n >= 64)
        {
            _mm512_store_si512(d_vec, _mm512_load_si512(s_vec));
            n -= 64;
            d_vec += 1;
            s_vec += 1;
        }
    }
    else
    {
        // Copy 1024 bytes at a time (16 * 64 bytes)
        while (n >= 1024)
        {
            _mm512_storeu_si512(d_vec, _mm512_loadu_si512(s_vec));
            _mm512_storeu_si512(d_vec + 1, _mm512_loadu_si512(s_vec + 1));
            _mm512_storeu_si512(d_vec + 2, _mm512_loadu_si512(s_vec + 2));
            _mm512_storeu_si512(d_vec + 3, _mm512_loadu_si512(s_vec + 3));
            _mm512_storeu_si512(d_vec + 4, _mm512_loadu_si512(s_vec + 4));
            _mm512_storeu_si512(d_vec + 5, _mm512_loadu_si512(s_vec + 5));
            _mm512_storeu_si512(d_vec + 6, _mm512_loadu_si512(s_vec + 6));
            _mm512_storeu_si512(d_vec + 7, _mm512_loadu_si512(s_vec + 7));
            _mm512_storeu_si512(d_vec + 8, _mm512_loadu_si512(s_vec + 8));
            _mm512_storeu_si512(d_vec + 9, _mm512_loadu_si512(s_vec + 9));
            _mm512_storeu_si512(d_vec + 10, _mm512_loadu_si512(s_vec + 10));
            _mm512_storeu_si512(d_vec + 11, _mm512_loadu_si512(s_vec + 11));
            _mm512_storeu_si512(d_vec + 12, _mm512_loadu_si512(s_vec + 12));
            _mm512_storeu_si512(d_vec + 13, _mm512_loadu_si512(s_vec + 13));
            _mm512_storeu_si512(d_vec + 14, _mm512_loadu_si512(s_vec + 14));
            _mm512_storeu_si512(d_vec + 15, _mm512_loadu_si512(s_vec + 15));
            n -= 1024;
            d_vec += 16;
            s_vec += 16;
        }

        // Copy 256 bytes at a time (4 * 64 bytes)
        while (n >= 256)
        {
            _mm512_storeu_si512(d_vec, _mm512_loadu_si512(s_vec));
            _mm512_storeu_si512(d_vec + 1, _mm512_loadu_si512(s_vec + 1));
            _mm512_storeu_si512(d_vec + 2, _mm512_loadu_si512(s_vec + 2));
            _mm512_storeu_si512(d_vec + 3, _mm512_loadu_si512(s_vec + 3));
            n -= 256;
            d_vec += 4;
            s_vec += 4;
        }

        // Copy 128 bytes at a time (2 * 64 bytes)
        while (n >= 128)
        {
            _mm512_storeu_si512(d_vec, _mm512_loadu_si512(s_vec));
            _mm512_storeu_si512(d_vec + 1, _mm512_loadu_si512(s_vec + 1));
            n -= 128;
            d_vec += 2;
            s_vec += 2;
        }

        // Copy 64 bytes at a time
        while (n >= 64)
        {
            _mm512_storeu_si512(d_vec, _mm512_loadu_si512(s_vec));
            n -= 64;
            d_vec += 1;
            s_vec += 1;
        }
    }

    // Copy any remaining bytes
    if (n > 0)
    {
        uint8_t       *d = (uint8_t *) d_vec;
        const uint8_t *s = (const uint8_t *) s_vec;

        if (((uintptr_t) d % 8 == 0) && ((uintptr_t) s % 8 == 0))
        {
            while (n >= 8)
            {
                *(uint64_t *) d = *(const uint64_t *) s;
                d += 8;
                s += 8;
                n -= 8;
            }
        }
        while (n--)
        {
            *d++ = *s++;
        }
    }
}

#define memoryCopyLarge memoryCopyAVX512

#elif ENABLE_MEMCOPY_AVX2 == 1

#include <x86intrin.h>
static inline void memoryCopyAVX2(void *dest, const void *src, intmax_t n)
{
    __m256i       *d_vec = (__m256i *) (dest);
    const __m256i *s_vec = (const __m256i *) (src);

    bool aligned = ((uintptr_t) dest % 32 == 0 && (uintptr_t) src % 32 == 0);

    if (aligned)
    {
        // Copy 512 bytes at a time
        while (n >= 512)
        {
            _mm256_store_si256(d_vec, _mm256_load_si256(s_vec));
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
            n -= 512;
            d_vec += 16;
            s_vec += 16;
        }

        // Copy 128 bytes at a time
        while (n >= 128)
        {
            _mm256_store_si256(d_vec, _mm256_load_si256(s_vec));
            _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vec + 1));
            _mm256_store_si256(d_vec + 2, _mm256_load_si256(s_vec + 2));
            _mm256_store_si256(d_vec + 3, _mm256_load_si256(s_vec + 3));
            n -= 128;
            d_vec += 4;
            s_vec += 4;
        }

        // Copy 64 bytes at a time
        while (n >= 64)
        {
            _mm256_store_si256(d_vec, _mm256_load_si256(s_vec));
            _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vec + 1));
            n -= 64;
            d_vec += 2;
            s_vec += 2;
        }

        // Copy 32 bytes at a time
        while (n >= 32)
        {
            _mm256_store_si256(d_vec, _mm256_load_si256(s_vec));
            n -= 32;
            d_vec += 1;
            s_vec += 1;
        }
    }
    else
    {
        // Copy 512 bytes at a time
        while (n >= 512)
        {
            _mm256_storeu_si256(d_vec, _mm256_loadu_si256(s_vec));
            _mm256_storeu_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
            _mm256_storeu_si256(d_vec + 2, _mm256_loadu_si256(s_vec + 2));
            _mm256_storeu_si256(d_vec + 3, _mm256_loadu_si256(s_vec + 3));
            _mm256_storeu_si256(d_vec + 4, _mm256_loadu_si256(s_vec + 4));
            _mm256_storeu_si256(d_vec + 5, _mm256_loadu_si256(s_vec + 5));
            _mm256_storeu_si256(d_vec + 6, _mm256_loadu_si256(s_vec + 6));
            _mm256_storeu_si256(d_vec + 7, _mm256_loadu_si256(s_vec + 7));
            _mm256_storeu_si256(d_vec + 8, _mm256_loadu_si256(s_vec + 8));
            _mm256_storeu_si256(d_vec + 9, _mm256_loadu_si256(s_vec + 9));
            _mm256_storeu_si256(d_vec + 10, _mm256_loadu_si256(s_vec + 10));
            _mm256_storeu_si256(d_vec + 11, _mm256_loadu_si256(s_vec + 11));
            _mm256_storeu_si256(d_vec + 12, _mm256_loadu_si256(s_vec + 12));
            _mm256_storeu_si256(d_vec + 13, _mm256_loadu_si256(s_vec + 13));
            _mm256_storeu_si256(d_vec + 14, _mm256_loadu_si256(s_vec + 14));
            _mm256_storeu_si256(d_vec + 15, _mm256_loadu_si256(s_vec + 15));
            n -= 512;
            d_vec += 16;
            s_vec += 16;
        }

        // Copy 128 bytes at a time
        while (n >= 128)
        {
            _mm256_storeu_si256(d_vec, _mm256_loadu_si256(s_vec));
            _mm256_storeu_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
            _mm256_storeu_si256(d_vec + 2, _mm256_loadu_si256(s_vec + 2));
            _mm256_storeu_si256(d_vec + 3, _mm256_loadu_si256(s_vec + 3));
            n -= 128;
            d_vec += 4;
            s_vec += 4;
        }

        // Copy 64 bytes at a time
        while (n >= 64)
        {
            _mm256_storeu_si256(d_vec, _mm256_loadu_si256(s_vec));
            _mm256_storeu_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
            n -= 64;
            d_vec += 2;
            s_vec += 2;
        }

        // Copy 32 bytes at a time
        while (n >= 32)
        {
            _mm256_storeu_si256(d_vec, _mm256_loadu_si256(s_vec));
            n -= 32;
            d_vec += 1;
            s_vec += 1;
        }
    }

    // Copy any remaining bytes
    if (n > 0)
    {
        uint8_t       *d = (uint8_t *) d_vec;
        const uint8_t *s = (const uint8_t *) s_vec;

        if (((uintptr_t) d % 8 == 0) && ((uintptr_t) s % 8 == 0))
        {
            while (n >= 8)
            {
                *(uint64_t *) d = *(const uint64_t *) s;
                d += 8;
                s += 8;
                n -= 8;
            }
        }
        while (n--)
        {
            *d++ = *s++;
        }
    }
}

#define memoryCopyLarge memoryCopyAVX2

#else

#define memoryCopyLarge memoryCopy

#endif

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

WW_EXPORT bool stringStartsWith(const char *str, const char *start);
WW_EXPORT bool stringEndsWith(const char *str, const char *end);
WW_EXPORT bool stringContains(const char *str, const char *sub);
WW_EXPORT bool stringWildCardMatch(const char *str, const char *pattern);

WW_EXPORT char *stringNewWithoutSpace(const char *str);

#if HAVE_STRLCPY

#define stringCopyN strlcpy

#else

// strncpy n = sizeof(dest_buf)-1
// stringCopyN n = sizeof(dest_buf)
WW_EXPORT char *stringCopyN(char *dest, const char *src, size_t n);

#endif

#if HAVE_STRLCAT

#define stringCat strlcat

#else

// strncat n = sizeof(dest_buf)-1-stringLength(dest)
// stringCopyN n = sizeof(dest_buf)
WW_EXPORT char *stringCat(char *dest, const char *src, size_t n);

#endif

#define stringChr strchr

WW_EXPORT char *stringChrLen(const char *s, char c, size_t n);

#define stringChrDot(str) strrchr(str, '.')
WW_EXPORT char *stringChrDir(const char *filepath);

#define stringCopy strcpy

//--------------------file-------------------------------

char *readFile(const char *path);
bool  writeFile(const char *path, const char *data, size_t len);

// basename
WW_EXPORT const char *filePathBaseName(const char *filepath);
WW_EXPORT const char *filePathSuffixName(const char *filename);
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
