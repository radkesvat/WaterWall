#include "rtmp_wire.h"

#include <string.h>

static const uint8_t kDataPrefix[] = {0x00, 0x02, 0x00, 0x07, 'w', 'w', '.', 'd', 'a', 't', 'a', 0x11, 0x0c};

size_t rtmpU29Encode(uint32_t value, uint8_t out[4])
{
    if (value > 0x1fffffffU)
        return 0;

    if (value >= 0x200000U)
    {
        out[0] = (uint8_t) (0x80U | (value >> 22U));
        out[1] = (uint8_t) (0x80U | ((value >> 15U) & 0x7fU));
        out[2] = (uint8_t) (0x80U | ((value >> 8U) & 0x7fU));
        out[3] = (uint8_t) value;
        return 4;
    }

    size_t used = 0;
    if (value >= 0x4000U)
        out[used++] = (uint8_t) (0x80U | (value >> 14U));
    if (value >= 0x80U)
        out[used++] = (uint8_t) (0x80U | ((value >> 7U) & 0x7fU));
    out[used++] = (uint8_t) (value & 0x7fU);
    return used;
}

size_t rtmpU29Decode(const uint8_t *bytes, size_t length, uint32_t *value)
{
    if (length == 0)
        return 0;

    uint32_t decoded = 0;
    for (size_t i = 0; i < length && i < 4; ++i)
    {
        if (i == 3)
        {
            decoded = (decoded << 8U) | bytes[i];
            if (decoded < 0x200000U)
                return 0;
        }
        else
        {
            decoded = (decoded << 7U) | (bytes[i] & 0x7fU);
            if ((bytes[i] & 0x80U) != 0)
                continue;
            if (i != 0 && decoded < (1U << (7U * i)))
                return 0;
        }

        *value = decoded;
        return i + 1;
    }
    return 0;
}

static size_t encodePrefix(size_t length, uint8_t out[RTMP_WIRE_PREFIX_MAX])
{
    if (length > RTMP_WIRE_DATA_MAX)
        return 0;
    uint8_t      u29[4];
    const size_t u29_size = rtmpU29Encode(((uint32_t) length << 1U) | 1U, u29);
    memcpy(out, kDataPrefix, sizeof(kDataPrefix));
    memcpy(out + sizeof(kDataPrefix), u29, u29_size);
    return sizeof(kDataPrefix) + u29_size;
}

size_t rtmpWireEncode(const uint8_t *data, size_t length, uint8_t *out, size_t capacity)
{
    uint8_t      prefix[RTMP_WIRE_PREFIX_MAX];
    const size_t prefix_size = encodePrefix(length, prefix);
    if (prefix_size == 0 || capacity < prefix_size + length)
        return 0;
    memcpy(out, prefix, prefix_size);
    if (length > 0)
        memcpy(out + prefix_size, data, length);
    return prefix_size + length;
}

bool rtmpWireDecode(const uint8_t *body, size_t length, const uint8_t **data, size_t *size)
{
    if (length <= sizeof(kDataPrefix) || length > RTMP_WIRE_BODY_MAX ||
        memcmp(body, kDataPrefix, sizeof(kDataPrefix)) != 0)
        return false;

    uint32_t     inline_length;
    const size_t u29_size = rtmpU29Decode(body + sizeof(kDataPrefix), length - sizeof(kDataPrefix), &inline_length);
    if (u29_size == 0 || (inline_length & 1U) == 0)
        return false;

    const size_t payload_size = inline_length >> 1U;
    const size_t prefix_size  = sizeof(kDataPrefix) + u29_size;
    if (payload_size > RTMP_WIRE_DATA_MAX || payload_size != length - prefix_size)
        return false;

    *data = body + prefix_size;
    *size = payload_size;
    return true;
}
