#ifndef WW_RTMP_WIRE_H
#define WW_RTMP_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    RTMP_WIRE_DATA_MAX   = 65536,
    RTMP_WIRE_PREFIX_MAX = 16,
    RTMP_WIRE_BODY_MAX   = RTMP_WIRE_DATA_MAX + RTMP_WIRE_PREFIX_MAX,
};

/* A zero result indicates invalid input or insufficient space. */
size_t rtmpU29Encode(uint32_t value, uint8_t out[4]);
size_t rtmpU29Decode(const uint8_t *bytes, size_t length, uint32_t *value);
size_t rtmpWireEncode(const uint8_t *data, size_t length, uint8_t *out, size_t capacity);
bool   rtmpWireDecode(const uint8_t *body, size_t length, const uint8_t **data, size_t *size);

#endif
