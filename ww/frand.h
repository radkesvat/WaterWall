#pragma once
#include "ww.h"

/*
    Generic random implementations, to be faster or provider other features...

    "frand_seed" is initialized by ww (generally time()) the seed is a global ww variable

    todo (seed update) the seed is 1 time initialized, i thinks its good if we update it in every idle cycles
*/


/*

Compute a pseudorandom integer.
Output value in range [0, 32767]

accessing this function from multiple threads will ofcourse corrupt the seed, since its not atomic
but that is actually good, the output can be true random !

about 2 times faster than default rand()
not a secure random!

*/
inline uint32_t fastRand(void)
{
    frand_seed = (214013 * frand_seed + 2531011);
    return (frand_seed >> 16) & 0x7FFF;
}
