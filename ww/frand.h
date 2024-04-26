#pragma once
#include "ww.h"
#include "utils/mathutils.h"

// seed initialized by ww (generally time())
// Compute a pseudorandom integer.
// Output value in range [0, 32767]
// accessing this function from multiple threads will ofcourse corrput the 
// last seed data, but thats actually good, the output will be true random!
inline unsigned int fastRand(void)
{
    frand_seed = (214013 * frand_seed + 2531011);
    return (frand_seed >> 16) & 0x7FFF;
}