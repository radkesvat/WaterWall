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
    /* Host-order TCP qualifiers; zero means unspecified. */
    uint16_t tcp_source_port;
    uint16_t tcp_destination_port;
} capture_protocol_filter_t;

static inline bool captureProtocolFilterHasTcpPorts(const capture_protocol_filter_t *filter)
{
    return filter->tcp_source_port != 0 || filter->tcp_destination_port != 0;
}

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
    if (captureProtocolFilterHasTcpPorts(filter))
        return false;
    for (size_t i = 0; i < kCaptureProtocolWordCount; ++i)
    {
        if (filter->excluded[i] != 0)
        {
            return false;
        }
    }
    return true;
}
