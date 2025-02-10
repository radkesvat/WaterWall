#pragma once

#include "wplatform.h"
#include "wtime.h"

#include "watomic.h"
#include "wdef.h"
#include "wendian.h"
#include "werr.h"
#include "wexport.h"
#include "wfrand.h"
#include "whash.h"
#include "wmath.h"

#include "ww_lwip.h"


void initWLibc(void);

//--------------------Memory-------------------------------

struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

void *memoryAllocate(size_t size);
void *memoryAllocateZero(size_t size);
void *memoryReAllocate(void *ptr, size_t size);
void  memoryFree(void *ptr);

void *memoryDedicatedAllocate(dedicated_memory_t *dm, size_t size);
void *memoryDedicatedReallocate(dedicated_memory_t *dm, void *ptr, size_t size);
void  memoryDedicatedFree(dedicated_memory_t *dm, void *ptr);

/* STC lib will use our custom allocators*/
#define c_malloc(sz) memoryAllocate((size_t)(sz))
#define c_calloc(n, sz) memoryAllocateZero((size_t)((n)* (sz)))
#define c_realloc(ptr, old_sz, sz) memoryReAllocate(ptr, (size_t)(sz))
#define c_free(ptr, sz) memoryFree(ptr)

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
    (void) buf;
    (void) size;
}

#endif

#ifndef MEM128_BUF_OPTIMIZE
#error "MEM128_BUF_OPTIMIZE must be defined to either 0 or 1"
#endif

#if MEM128_BUF_OPTIMIZE == 0

#define memoryCopy128 memoryCopy

#elif defined(WW_AVX) && defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))

#include <x86intrin.h>
static inline void memoryCopy128(void *dest, const void *src, intmax_t n)
{
    __m256i       *d_vec = (__m256i *) (dest);
    const __m256i *s_vec = (const __m256i *) (src);

    if ((uintptr_t) dest % 128 != 0 || (uintptr_t) src % 128 != 0)
    {

        while (n > 0)
        {
            _mm256_storeu_si256(d_vec, _mm256_loadu_si256(s_vec));
            _mm256_storeu_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
            _mm256_storeu_si256(d_vec + 2, _mm256_loadu_si256(s_vec + 2));
            _mm256_storeu_si256(d_vec + 3, _mm256_loadu_si256(s_vec + 3));

            n -= 128;
            d_vec += 4;
            s_vec += 4;
        }

        return;
    }

    while (n > 0)
    {
        _mm256_store_si256(d_vec, _mm256_load_si256(s_vec));
        _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vec + 1));
        _mm256_store_si256(d_vec + 2, _mm256_load_si256(s_vec + 2));
        _mm256_store_si256(d_vec + 3, _mm256_load_si256(s_vec + 3));

        n -= 128;
        d_vec += 4;
        s_vec += 4;
    }
}

#else

static inline void memoryCopy128(uint8_t *__restrict _dest, const uint8_t *__restrict _src, intmax_t n)
{

    while (n > 0)
    {
        memoryCopy(_dest, _src, 128);
        n -= 128;
        _dest += 128;
        _src += 128;
    }
}

#endif

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


WW_EXPORT char* stringNewWithoutSpace(const char *str);

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

// strncat n = sizeof(dest_buf)-1-strlen(dest)
// stringCopyN n = sizeof(dest_buf)
WW_EXPORT char *stringCat(char *dest, const char *src, size_t n);

#endif

#define stringChr strchr

WW_EXPORT char *stringChrLen(const char *s, char c, size_t n);

#define stringChrDot(str) strrchr(str, '.')
WW_EXPORT char *stringChrDir(const char *filepath);

//--------------------file-------------------------------

char *readFile(const char *path);
bool  writeFile(const char *path, const char *data, size_t len);

// basename
WW_EXPORT const char *filePathBaseName(const char *filepath);
WW_EXPORT const char *filePathSuffixName(const char *filename);
// mkdir -p
WW_EXPORT int createDirIfNotExists(const char *dir);
// rmdir -p
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


static void printDebug(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}

static void printError(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

static void printHex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
    fflush(stdout);
}

