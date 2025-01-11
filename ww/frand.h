#pragma once
#include "worker.h"

/*
    Generic random implementations, to be faster or provide other features...
*/


// access to correctly aligned variables are atomic
extern uint32_t frand_seed32;
extern uint64_t frand_seed64;



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
    uint32_t rot        = frand_seed64 >> 59U;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

// every thread should call this once
// this will not initalize for dynamic loaded libs as far as i know
// but it is ok , it is not a secure random anyway
static inline void frandInit(void)
{
    frand_seed32 = time(NULL);
    frand_seed64 = time(NULL);
}
