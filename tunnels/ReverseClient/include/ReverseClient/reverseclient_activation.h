#pragma once

#include "wlibc.h"

/* One prefix per assigned reverse transport: a big-endian total length,
 * including this header, followed by random bytes. The remaining stream is
 * application data. These wire bounds do not depend on server JSON settings. */
enum
{
    kReverseActivationHeaderSize     = 4,
    kReverseActivationMaxSize        = 65536,
    kReverseActivationDefaultMinSize = 64,
    kReverseActivationDefaultMaxSize = 1024
};

static inline uint32_t reverseActivationReadSize(const uint8_t *bytes)
{
    return ((uint32_t) bytes[0] << 24) | ((uint32_t) bytes[1] << 16) | ((uint32_t) bytes[2] << 8) | bytes[3];
}

static inline void reverseActivationWriteSize(uint8_t *bytes, uint32_t size)
{
    bytes[0] = (uint8_t) (size >> 24);
    bytes[1] = (uint8_t) (size >> 16);
    bytes[2] = (uint8_t) (size >> 8);
    bytes[3] = (uint8_t) size;
}
