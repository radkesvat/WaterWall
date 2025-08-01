#pragma once
#include "wlibc.h"

#ifdef COMPILER_MSVC
#pragma warning(disable : 4146) // unary minus operator applied to unsigned type, result still unsigned
#endif

/*
    Generic random implementations, to be faster or provide other features...
*/

// access to correctly aligned variables are atomic
extern thread_local uint32_t frand_seed32;
extern thread_local uint64_t frand_seed64;

/*

    Compute a pseudorandom integer.
    Output value in range [0, 32767]

    about 2 times faster than default rand()
    not a secure random!

*/
static inline uint32_t fastRand(void)
{
    frand_seed32 = (214013 * frand_seed32 + 2531011);
    return (frand_seed32 >> 16) & 0x7FFF;
}

/*
    Compute a pseudorandom integer.
    Output value in range of 32 bits
*/
static inline uint32_t fastRand32(void)
{

    frand_seed64        = frand_seed64 * 6364136223846793005ULL + 13971ULL;
    uint32_t xorshifted = (uint32_t) (((frand_seed64 >> 18U) ^ frand_seed64) >> 27U);
    uint32_t rot        = (uint32_t) (frand_seed64 >> 59U);
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

/*
    Compute a pseudorandom integer.
    Output value in range of 64 bits
*/
static inline uint64_t fastRand64(void)
{
    // Generate two 32-bit values using the PCG algorithm
    uint32_t high = fastRand32();
    uint32_t low = fastRand32();
    return ((uint64_t)high << 32) | low;
}

static void getRandomBytes(void *bytes, size_t size)
{
    uint8_t *b = (uint8_t *) bytes;
    size_t i = 0;
    
    // Fill 8 bytes at a time when properly aligned
    while (i + 8 <= size && ((uintptr_t)(b + i) % 8 == 0))
    {
        *((uint64_t *)(b + i)) = fastRand64();
        i += 8;
    }
    
    // Fill 4 bytes at a time when properly aligned
    while (i + 4 <= size && ((uintptr_t)(b + i) % 4 == 0))
    {
        *((uint32_t *)(b + i)) = fastRand32();
        i += 4;
    }
    
    // Fill remaining bytes one by one
    uint32_t rand_val = 0;
    int rand_bytes_left = 0;
    
    while (i < size)
    {
        if (rand_bytes_left == 0)
        {
            rand_val = fastRand32();
            rand_bytes_left = 4;
        }
        b[i++] = (uint8_t)(rand_val & 0xFF);
        rand_val >>= 8;
        rand_bytes_left--;
    }
}

// every thread should call this once
// this will not initalize for dynamic loaded libs as far as i know
// but it is ok , it is not a secure random anyway
static inline void frandInit(void)
{
    // Use more entropy sources for better initialization
    uint64_t t = (uint64_t) time(NULL);
    uint64_t p = (uint64_t) (uintptr_t) &t; // stack address for some randomness
    
    frand_seed32 = (uint32_t) (t ^ (p >> 32));
    frand_seed64 = t ^ (p << 1) ^ 0x123456789ABCDEFULL;
    
    // Warm up the generators
    for (int i = 0; i < 10; i++)
    {
        fastRand();
        fastRand32();
        fastRand64();
    }
}
