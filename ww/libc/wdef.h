#ifndef WW_DEF_H_
#define WW_DEF_H_

#include "wplatform.h"

#ifndef ABS
#define ABS(n)              ((n) > 0 ? (n) : -(n))
#endif

#ifndef NABS
#define NABS(n)             ((n) < 0 ? (n) : -(n))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(*(a)))
#endif

#ifndef BITSET
#define BITSET(p, n)        (*(p) |= (1u << (n)))
#endif

#ifndef BITCLR
#define BITCLR(p, n)        (*(p) &= ~(1u << (n)))
#endif

#ifndef BITGET
#define BITGET(i, n)        ((i) & (1u << (n)))
#endif

#define FLOAT_PRECISION     1e-6
#define FLOAT_EQUAL_ZERO(f) (ABS(f) < FLOAT_PRECISION)

#ifndef INFINITE
#define INFINITE            (uint32_t)-1
#endif

#ifndef IS_ALPHA
#define IS_ALPHA(c)         (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))
#endif

#ifndef IS_DIGIT
#define IS_DIGIT(c)         ((c) >= '0' && (c) <= '9')
#endif

#ifndef IS_ALPHANUM
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_DIGIT(c))
#endif

#ifndef IS_CNTRL
#define IS_CNTRL(c)         ((c) >= 0 && (c) < 0x20)
#endif

#ifndef IS_GRAPH
#define IS_GRAPH(c)         ((c) >= 0x20 && (c) < 0x7F)
#endif

#ifndef IS_HEX
#define IS_HEX(c)           (IS_DIGIT(c) || ((c) >= 'a' && (c) <= 'f') || ((c) >= 'A' && (c) <= 'F'))
#endif

#ifndef IS_LOWER
#define IS_LOWER(c)         (((c) >= 'a' && (c) <= 'z'))
#endif

#ifndef IS_UPPER
#define IS_UPPER(c)         (((c) >= 'A' && (c) <= 'Z'))
#endif

#ifndef LOWER
#define LOWER(c)            ((c) | 0x20)
#endif

#ifndef UPPER
#define UPPER(c)            ((c) & ~0x20)
#endif

#ifndef LLD
#define LLD(v)              ((long long)(v))
#endif

#ifndef LLU
#define LLU(v)              ((unsigned long long)(v))
#endif

#ifndef _WIN32

#ifndef MAKEWORD
#define MAKEWORD(h, l)      ((((WORD)h) << 8) | (l & 0xff))
#endif

#ifndef HIBYTE
#define HIBYTE(w)           ((BYTE)(((WORD)w) >> 8))
#endif

#ifndef LOBYTE
#define LOBYTE(w)           ((BYTE)(w & 0xff))
#endif

#ifndef MAKELONG
#define MAKELONG(h, l)      (((int32_t)h) << 16 | (l & 0xffff))
#endif

#ifndef HIWORD
#define HIWORD(n)           ((WORD)(((int32_t)n) >> 16))
#endif

#ifndef LOWORD
#define LOWORD(n)           ((WORD)(n & 0xffff))
#endif

#endif // _WIN32

#ifndef MAKEINT64
#define MAKEINT64(h, l)     (((int64_t)h) << 32 | (l & 0xffffffff))
#endif

#ifndef HIINT
#define HIINT(n)            ((int32_t)(((int64_t)n) >> 32))
#endif

#ifndef LOINT
#define LOINT(n)            ((int32_t)(n & 0xffffffff))
#endif

#ifndef MAKE_FOURCC
#define MAKE_FOURCC(a, b, c, d) \
                            (((uint32)d) | (((uint32)c) << 8) | (((uint32)b) << 16) | (((uint32)a) << 24))
#endif

#ifndef MAX
#define MAX(a, b)           ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#endif

#ifndef LIMIT
#define LIMIT(lower, v, upper) \
                            ((v) < (lower) ? (lower) : (v) > (upper) ? (upper) : (v))
#endif

#ifndef MAX_PATH
#define MAX_PATH            260
#endif

#ifndef NULL
#ifdef __cplusplus
#define NULL                0
#else
#define NULL                ((void*)0)
#endif
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef SAFE_ALLOC
#define SAFE_ALLOC(p, size) \
    do { \
        void* ptr = memoryAllocate(size); \
        if (!ptr) { \
            printError("malloc failed!\n"); \
            exit(-1); \
        } \
        memorySet(ptr, 0, size); \
        *(void**)&(p) = ptr; \
    } while(0)
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(p)        do {if (p) {memoryFree(p); (p) = NULL;}} while(0)
#endif

#ifndef SAFE_DELETE
#define SAFE_DELETE(p)      do {if (p) {delete (p); (p) = NULL;}} while(0)
#endif

#ifndef SAFE_DELETE_ARRAY
#define SAFE_DELETE_ARRAY(p) \
                            do {if (p) {delete[] (p); (p) = NULL;}} while(0)
#endif

#ifndef SAFE_RELEASE
#define SAFE_RELEASE(p)     do {if (p) {(p)->release(); (p) = NULL;}} while(0)
#endif

#ifndef SAFE_CLOSE
#define SAFE_CLOSE(fd)      do {if ((fd) >= 0) {close(fd); (fd) = -1;}} while(0)
#endif

#define STRINGIFY(x)        STRINGIFY_HELPER(x)
#define STRINGIFY_HELPER(x) #x

#define STRINGCAT(x, y)     STRINGCAT_HELPER(x, y)
#define STRINGCAT_HELPER(x, y) \
                            x##y

#ifndef offsetof
#define offsetof(type, member) \
                            ((size_t)(&((type*)0)->member))
#endif

#ifndef offsetofend
#define offsetofend(type, member) \
                            (offsetof(type, member) + sizeof(((type*)0)->member))
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
                            ((type*)((char*)(ptr) - offsetof(type, member)))
#endif

#ifdef PRINT_DEBUG
#define printd(...)         printf(__VA_ARGS__)
#else
#define printd(...)
#endif

#ifdef PRINT_ERROR
#define printe(...)         printError(__VA_ARGS__)
#else
#define printe(...)
#endif

#if !defined(COMPILER_MSVC)

#define LIKELY(x)           __builtin_expect(x, 1)
#define UNLIKELY(x)         __builtin_expect(x, 0)

#else

#define LIKELY(x)           (x)
#define UNLIKELY(x)         (x)
#endif

enum
{
#if defined(__i386__) || defined(__x86_64__)
    kCpuLineCacheSize = 64
#elif defined(__arm__) || defined(__aarch64__)
    kCpuLineCacheSize = 64
#elif defined(__powerpc64__)
    kCpuLineCacheSize = 128
#else
    kCpuLineCacheSize = 64
#endif
    ,
    kCpuLineCacheSizeMin1 = (kCpuLineCacheSize - 1)
};

#if defined(__i386__) || defined(__x86_64__)
#define CPULINECACHESIZE    64
#elif defined(__arm__) || defined(__aarch64__)
#define CPULINECACHESIZE    64
#elif defined(__powerpc64__)
#define CPULINECACHESIZE    128
#else
#define CPULINECACHESIZE    64
#endif

#define CPULINECACHESIZEMIN1 (kCpuLineCacheSize - 1)

#ifdef COMPILER_MSVC

#define MSVC_ATTR_ALIGNED_LINE_CACHE __declspec(align(CPULINECACHESIZE))
#define MSVC_ATTR_ALIGNED_16         __declspec(align(16))
#define GNU_ATTR_ALIGNED_LINE_CACHE
#define GNU_ATTR_ALIGNED_16

#else

#define MSVC_ATTR_ALIGNED_LINE_CACHE
#define MSVC_ATTR_ALIGNED_16
#define GNU_ATTR_ALIGNED_LINE_CACHE  __attribute__((aligned(kCpuLineCacheSize)))
#define GNU_ATTR_ALIGNED_16          __attribute__((aligned(16)))

#endif

#define MUSTALIGN2(n, w)    assert(((w) & ((w) -1)) == 0); /* alignment w is not a power of two */

#define ALIGN2(n, w)        (uintptr_t)(((uintptr_t)(n) + ((uintptr_t)(w) -1)) & ~(((uintptr_t)(w)) -1))

#define memoryCopy          memcpy
#define memorySet           memset
#define memoryMove          memmove
#define memoryCompare       memcmp
#define stringLength        strlen

#ifndef thread_local
#if __STDC_VERSION__ >= 201112 && !defined __STDC_NO_THREADS__
#define thread_local        _Thread_local
#elif defined _WIN32 && (defined _MSC_VER || defined __ICL || defined __DMC__ || defined __BORLANDC__)
#define thread_local        __declspec(thread)
#elif defined __GNUC__ || defined __SUNPRO_C || defined __hpux || defined __xlC__
#define thread_local        __thread
#else
#error "Cannot define thread_local"
#endif
#endif

#ifdef COMPILER_MSVC

    #define STDIN_FILENO        _fileno(stdin)
    #define STDOUT_FILENO       _fileno(stdout)
    #define STDERR_FILENO       _fileno(stderr)

    #if !defined(ssize_t)
        #ifdef _WIN64
        typedef __int64 ssize_t;  // 64-bit Windows
        #define SSIZE_MAX INT64_MAX

        #else
        typedef int ssize_t;      // 32-bit Windows
        #define SSIZE_MAX INT_MAX

        #endif
    #endif

#endif

#ifdef OS_WIN
    #define INVALID_SOCKET_VALUE INVALID_SOCKET
#else
    #define INVALID_SOCKET_VALUE -1
#endif


typedef uint8_t   u8_t;
typedef int8_t    s8_t;
typedef uint16_t  u16_t;
typedef int16_t   s16_t;
typedef uint32_t  u32_t;
typedef int32_t   s32_t;
#if LWIP_HAVE_INT64
typedef uint64_t  u64_t;
typedef int64_t   s64_t;
#endif
typedef uintptr_t mem_ptr_t;


#endif // WW_DEF_H_
