#pragma once

#include "wlibc.h"

enum
{
    kCaptureIpProtocolCount         = 256,
    kCaptureProtocolWordCount       = kCaptureIpProtocolCount / 32,
    kCaptureLinuxProtocolFilterSize = 1024
};

/* A zeroed set excludes nothing. Each value is the literal IPv4 Protocol byte. */
typedef struct capture_protocol_filter_s
{
    uint32_t excluded[kCaptureProtocolWordCount];
} capture_protocol_filter_t;

static inline void captureProtocolFilterExclude(capture_protocol_filter_t *filter, uint8_t protocol)
{
    filter->excluded[protocol / 32U] |= UINT32_C(1) << (protocol % 32U);
}

static inline bool captureProtocolFilterExcludes(const capture_protocol_filter_t *filter, uint8_t protocol)
{
    return (filter->excluded[protocol / 32U] & (UINT32_C(1) << (protocol % 32U))) != 0;
}

static inline bool captureProtocolFilterIsEmpty(const capture_protocol_filter_t *filter)
{
    for (size_t i = 0; i < kCaptureProtocolWordCount; ++i)
    {
        if (filter->excluded[i] != 0)
        {
            return false;
        }
    }
    return true;
}
