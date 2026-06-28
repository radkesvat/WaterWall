#pragma once

#include "wlibc.h"

enum
{
    kWwUuidBytesLen           = 16,
    kWwUuidCanonicalStringLen = 36
};

static inline bool wwUuidParseString(const char *text, uint8_t out[kWwUuidBytesLen])
{
    if (text == NULL)
    {
        return false;
    }

    size_t len    = stringLength(text);
    bool   dashed = len == kWwUuidCanonicalStringLen;

    if (len != kWwUuidBytesLen * 2U && len != kWwUuidCanonicalStringLen)
    {
        return false;
    }

    memoryZero(out, kWwUuidBytesLen);

    size_t hex_index = 0;
    for (size_t i = 0; i < len; ++i)
    {
        if (dashed && (i == 8U || i == 13U || i == 18U || i == 23U))
        {
            if (text[i] != '-')
            {
                return false;
            }
            continue;
        }

        if (text[i] == '-')
        {
            return false;
        }

        int value = asciiHexValue((uint8_t) text[i]);
        if (value < 0 || hex_index >= kWwUuidBytesLen * 2U)
        {
            return false;
        }

        if ((hex_index & 1U) == 0)
        {
            out[hex_index / 2U] = (uint8_t) (value << 4U);
        }
        else
        {
            out[hex_index / 2U] |= (uint8_t) value;
        }
        ++hex_index;
    }

    return hex_index == kWwUuidBytesLen * 2U;
}

static inline void wwUuidToCanonicalString(const uint8_t uuid[kWwUuidBytesLen],
                                           char          out[kWwUuidCanonicalStringLen + 1U])
{
    size_t off = 0;

    for (size_t i = 0; i < kWwUuidBytesLen; ++i)
    {
        if (i == 4U || i == 6U || i == 8U || i == 10U)
        {
            out[off++] = '-';
        }

        out[off++] = (char) asciiHexDigitLower((uint8_t) ((uuid[i] >> 4U) & 0x0FU));
        out[off++] = (char) asciiHexDigitLower((uint8_t) (uuid[i] & 0x0FU));
    }

    out[off] = '\0';
}
