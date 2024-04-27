#pragma once
#include "ww.h"
#include "utils/mathutils.h"

/*
    about 2 times faster than default rand()
    not a secure random!
    not a secure random!
    not a secure random!
*/

// seed initialized by ww (generally time()) the seed is a global ww variable

// Compute a pseudorandom integer.
// Output value in range [0, 32767]
// accessing this function from multiple threads will ofcourse corrupt the seed
// but thats actually good, the output can be true random !
inline unsigned int fastRand(void)
{
    frand_seed = (214013 * frand_seed + 2531011);
    return (frand_seed >> 16) & 0x7FFF;
}
