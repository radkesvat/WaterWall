#pragma once
#include "ww.h"

/*
    Generic random implementations, to be faster or provide other features...
*/

/*

    Compute a pseudorandom integer.
    Output value in range [0, 32767]

    about 2 times faster than default rand()
    not a secure random!

*/
extern _Thread_local bool         frand_initialized;
extern _Thread_local unsigned int frand_seed;

static inline uint32_t fastRand(void)
{
    if (WW_UNLIKELY(! frand_initialized))
    {
        frand_initialized = true;
        frand_seed        = time(NULL);
    }
    frand_seed = (214013 * frand_seed + 2531011);
    return (frand_seed >> 16) & 0x7FFF;
}
