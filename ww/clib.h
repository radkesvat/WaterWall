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


// **** Memory ****

static inline void memoryCopy(void *Dst, void const *Src, size_t Size)
{
    memcpy(Dst, Src, Size);
}

static inline void memoryMove(void *Dst, void const *Src, size_t Size)
{
    memmove(Dst, Src, Size);
}

typedef void *(*thread_routine_t)(void *);
void *createThread(thread_routine_t fn, void *userdata);
void  joinThread(void *handle);

static void *memoryAllocate(size_t size);
static void *memoryReAllocate(void *ptr, size_t size);
static void  memoryFree(void *ptr);
static void *memoryDedicatedAllocate(void *dm, size_t size);
static void *memoryDedicatedReallocate(void *dm, void *ptr, size_t size);
static void  memoryDedicatedFree(void *dm, void *ptr);

// **** Process ID ****

#ifdef OS_WIN
#define getProcessID (long) GetCurrentProcessId
#else
#define getProcessID (long) getpid
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

// **** Atomic ****

#if !HAVE_STDATOMIC_H

// c11
#include <stdatomic.h>

#define atomicAdd    atomic_fetch_add
#define atomicLoad   atomic_load
#define atomicStore  atomic_store
#define atomicSub    atomic_fetch_sub
#define atomicInc(p) atomicAdd(p, 1)
#define atomicDec(p) atomicSub(p, 1)

#define atomicAddExplicit       atomic_fetch_add_explicit
#define atomicLoadExplicit      atomic_load_explicit
#define atomicStoreExplicit     atomic_store_explicit
#define atomicSubExplicit       atomic_fetch_sub_explicit
#define atomicIncExplicit(p, x) atomicAddExplicit(p, x, 1)
#define atomicDecExplicit(p, x) atomicSubExplicit(p, x, 1)

#define atomicCompareExchange         atomic_compare_exchange_strong
#define atomicCompareExchangeExplicit atomic_compare_exchange_strong_explicit

#define atomicFlagTestAndSet atomic_flag_test_and_set
#define atomicFlagClear      atomic_flag_clear

#else

typedef volatile bool atomic_bool;
typedef volatile char atomic_char;
typedef volatile unsigned char atomic_uchar;
typedef volatile short atomic_short;
typedef volatile unsigned short atomic_ushort;
typedef volatile int atomic_int;
typedef volatile unsigned int atomic_uint;
typedef volatile long atomic_long;
typedef volatile unsigned long atomic_ulong;
typedef volatile long long atomic_llong;
typedef volatile unsigned long long atomic_ullong;
typedef volatile size_t atomic_size_t;

typedef struct atomic_flag
{
    atomic_bool _Value;
} atomic_flag;

#ifdef _WIN32

static inline bool atomicFlagTestAndSet(atomic_flag *p)
{
    // return InterlockedIncrement((LONG*)&p->_Value, 1);
    return InterlockedCompareExchange((LONG *) &p->_Value, 1, 0);
}

#define atomicAdd       InterlockedAdd
#define atomicSub(p, n) InterlockedAdd(p, -n)

#define atomicInc InterlockedIncrement
#define atomicDec InterlockedDecrement

#define atomicCompareExchange         InterlockedCompareExchange
#define atomicCompareExchangeExplicit atomicCompareExchange

#elif defined(__GNUC__)

static inline bool atomicFlagTestAndSet(atomic_flag *p)
{
    return ! __sync_bool_compare_and_swap(&p->_Value, 0, 1);
}

#define atomicAdd    __sync_fetch_and_add
#define atomicSub    __sync_fetch_and_sub
#define atomicInc(p) atomicAdd(p, 1)
#define atomicDec(p) atomicSub(p, 1)

#endif

#define atomicLoad(x)     (x)
#define atomicStore(X, y) (x) = (y)

#define atomicAddExplicit(X, y, z)   atomicAdd((X), (y))
#define atomicLoadExplicit(X, y, z)  atomicLoad((X), (y))
#define atomicStoreExplicit(X, y, z) atomicStore((X), (y))

#define atomicSubExplicit(X, y, z) atomicSub((X), (y))
#define atomicIncExplicit(p, x)    atomicAddExplicit(p, x, 1)
#define atomicDecExplicit(p, x)    atomicSubExplicit(p, x, 1)

static inline bool atomicFlagClear(atomic_flag *p)
{
    p->_Value = 0;
}

#endif


int createDirectoryIfNotExists(const char* dir);





























// NOLINTEND
