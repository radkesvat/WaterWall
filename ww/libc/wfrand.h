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

static void getRandomBytes(void *bytes, size_t size)
{
    uint8_t *b = (uint8_t *) bytes;
    for (size_t i = 0; i < size / 4; i++)
    {
        ((uint32_t *) b)[i] = fastRand32();
    }
    const size_t remainder = size % 4;
    for (size_t i = 0; i < remainder; i++)
    {
        b[size - remainder + i] = fastRand32() & 0xFF;
    }
}

// every thread should call this once
// this will not initalize for dynamic loaded libs as far as i know
// but it is ok , it is not a secure random anyway
static inline void frandInit(void)
{
    frand_seed32 = (uint32_t) time(NULL);
    frand_seed64 = (uint64_t) time(NULL);
}
