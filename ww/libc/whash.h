#pragma once
#include <stddef.h>
#include <stdint.h>

/*
    Some general and performant 64bit hash calculaction functions

    todo (benchmark) komihash vs Flower–Noll–Vo
    todo (siphash) add sip hash
*/

typedef uint64_t hash_t;

// zero as seed provides more performance
enum
{
    kKomihashSeed = 0,
};

#define K_FNV_SEED 0xCBF29CE484222325

// Flower–Noll–Vo
#if WHASH_ALG == FNV_HASH

static inline uint64_t hashFnv1a64(const uint8_t *buf, size_t len, uint64_t seed)
{
    const uint64_t prime = 0x100000001B3; // pow(2,40) + pow(2,8) + 0xb3
    const uint8_t *end   = buf + len;
    while (buf < end)
    {
        seed = (*buf++ ^ seed) * prime;
    }
    return seed;
}

static inline hash_t calcHashBytesSeed(const void *data, size_t len, uint64_t seed)
{
    return hashFnv1a64(data, len, seed);
}

#elif WHASH_ALG == KOMI_HASH

// Komi-Hash
#ifndef COMPILER_MSVC
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic" // int128 is not iso c (already macro guarded, no worries)
#include "komihash.h"
#pragma GCC diagnostic pop
#else
#include "komihash.h"
#endif

static inline hash_t calcHashBytesSeed(const void *data, size_t len, uint64_t seed)
{
    return komihash(data, len, seed);
}

static inline hash_t calcHashBytes(const void *data, size_t len)
{
    return calcHashBytesSeed(data, len, kKomihashSeed);
}

#else
#error "hash alg not selecetd!"
#endif
