#pragma once
#include <stdint.h>
#include <stddef.h>

static inline uint64_t hashFnv1a64(const uint8_t *buf, size_t len)
{
    const uint64_t prime = 0x100000001B3;      // pow(2,40) + pow(2,8) + 0xb3
    uint64_t       hash  = 0xCBF29CE484222325; // seed
    const uint8_t *end   = buf + len;
    while (buf < end)
    {
        hash = (*buf++ ^ hash) * prime;
    }
    return hash;
}

#define CALC_HASH_PRIMITIVE(x)  hashFnv1a64((const uint8_t *) &(x), sizeof((x)))
#define CALC_HASH_BYTES(x, len) hashFnv1a64((const uint8_t *) (x), (len))

// zero as seed provides more performanceo
// #define KOMIHASH_SEED 0
// #define CALC_HASH_PRIMITIVE(x)  komihash((x), sizeof((x)), KOMIHASH_SEED)
// #define CALC_HASH_BYTES(x, len) komihash((x), len, KOMIHASH_SEED)
