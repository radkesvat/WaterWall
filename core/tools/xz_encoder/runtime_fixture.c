#include <stdint.h>

/* A real native module for the encoder/decoder boundary test; never loaded. */
static uint32_t mix(uint32_t value)
{
    return (value ^ (value >> 13)) * 0x85ebca6bU;
}

uint32_t waterwallRuntimeFixture(uint32_t seed)
{
    for (unsigned int i = 0; i < 4096; ++i)
        seed = mix(seed + i);
    return seed;
}
