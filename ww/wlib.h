#pragma once

/*

    i like to have every depended function in one file, lets see how it goes...


*/
#include "hplatform.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// NOLINTBEGIN

#if defined(OS_UNIX)
#include <sys/types.h>
#endif


#if defined(_MSC_VER)
#define WWEXPORT __declspec(dllexport)
#elif defined(__GNUC__)
#define WWEXPORT __attribute__((visibility("default")))
#else
#define WWEXPORT
#endif

// **** Cache & Optimization ****

#if defined(__GNUC__) || defined(__clang__) || defined(__IBMC__) || defined(__IBMCPP__) || defined(__COMPCERT__)

#define LIKELY(x)   __builtin_expect(x, 1)
#define UNLIKELY(x) __builtin_expect(x, 0)

#else

#define LIKELY(x)   (v)
#define UNLIKELY(x) (v)
#endif

/*
    kCpuLineCacheSize is the size of a cache line of the target CPU.
    The value 64 covers i386, x86_64, arm32, arm64.
*/
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

    kCpuLineCacheSizeMin1 = kCpuLineCacheSize - 1
};

#define ATTR_ALIGNED_LINE_CACHE __attribute__((aligned(kCpuLineCacheSize)))

#define MUSTALIGN2(n, w) assert(((w) & ((w) -1)) == 0); /* alignment w is not a power of two */

#define ALIGN2(n, w) (((n) + ((w) -1)) & ~((w) -1))

#if defined(WW_AVX) && defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))

#include <x86intrin.h>
static inline void memoryCopy128(void *dest, const void *src, long int n)
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

static inline void memoryCopy128(uint8_t *__restrict _dest, const uint8_t *__restrict _src, size_t n)
{
    while (n > 0)
    {
        memcpy(_dest, _src, 128);
        n -= 128;
        _dest += 128;
        _src += 128;
    }
}

#endif





























// NOLINTEND
