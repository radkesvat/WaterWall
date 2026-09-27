#pragma once

/* Private arithmetic shared with fragment validation and reconstruction. */
#include "wlibc.h"

static inline uint16_t deviceIpv4HeaderChecksum(const uint8_t *packet, uint32_t header_len)
{
    uint32_t sum = 0;

    for (uint32_t i = 0; i < header_len; i += 2U)
    {
        sum += GET_BE16(packet + i);
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    return (uint16_t) ~sum;
}

static inline bool deviceIpv4HeaderChecksumValid(const uint8_t *packet, uint32_t header_len)
{
    return deviceIpv4HeaderChecksum(packet, header_len) == 0;
}
