#pragma once
#include <stddef.h>
#include <stdint.h>

/*
    Some general and performant 64bit hash calculaction functions


*/


// todo (benchmark) komihash vs Flower–Noll–Vo
// todo (siphash) add sip hash



//Flower–Noll–Vo
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

// #define CALC_HASH_PRIMITIVE(x)  hashFnv1a64((const uint8_t *) &(x), sizeof((x)))
// #define CALC_HASH_BYTES(x, len) hashFnv1a64((const uint8_t *) (x), (len))






// Komi-Hash

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "komihash.h"
#pragma GCC diagnostic pop


// zero as seed provides more performance
#define KOMIHASH_SEED           0
#define CALC_HASH_PRIMITIVE(x)  komihash((const uint8_t *) &(x), sizeof((x)), KOMIHASH_SEED)
#define CALC_HASH_BYTES(x, len) komihash((x), len, KOMIHASH_SEED)
