#include "KcpCommon/session.h"

static uint32_t read32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24U) | ((uint32_t) p[1] << 16U) | ((uint32_t) p[2] << 8U) | p[3];
}

static void write32(uint8_t *p, uint32_t n)
{
    p[0] = (uint8_t) (n >> 24U);
    p[1] = (uint8_t) (n >> 16U);
    p[2] = (uint8_t) (n >> 8U);
    p[3] = (uint8_t) n;
}

bool touNonceIsZero(const uint8_t nonce[kTouNonceSize])
{
    uint8_t value = 0;
    for (size_t i = 0; i < kTouNonceSize; ++i)
    {
        value |= nonce[i];
    }
    return value == 0;
}

void touNonceGenerate(uint8_t nonce[kTouNonceSize])
{
    do
    {
        getRandomBytes(nonce, kTouNonceSize);
    } while (touNonceIsZero(nonce));
}

uint64_t touDeadline(uint64_t start, uint32_t interval)
{
    return start > UINT64_MAX - interval ? UINT64_MAX : start + interval;
}

bool touSettingsDecode(const uint8_t *body, size_t size, tou_settings_t *settings)
{
    if (body == NULL || size != kTouSettingsSize || body[6] != 0 || body[7] != 0)
    {
        return false;
    }
    tou_settings_t s = {.close_ms = read32(body), .data_shards = body[4], .parity_shards = body[5]};
    if (s.close_ms == 0 || s.close_ms > INT_MAX || (s.data_shards == 0) != (s.parity_shards == 0) ||
        (unsigned) s.data_shards + s.parity_shards > 255U)
    {
        return false;
    }
    *settings = s;
    return true;
}

void touSettingsEncode(uint8_t body[kTouSettingsSize], const tou_settings_t *settings)
{
    write32(body, settings->close_ms);
    body[4] = settings->data_shards;
    body[5] = settings->parity_shards;
    body[6] = body[7] = 0;
}

bool touSettingsEqual(const tou_settings_t *a, const tou_settings_t *b)
{
    return a->close_ms == b->close_ms && a->data_shards == b->data_shards && a->parity_shards == b->parity_shards;
}

bool touWireDecode(const uint8_t *packet, size_t size, tou_wire_t *wire)
{
    if (packet == NULL || size < kTouEnvelopeSize || size - kTouEnvelopeSize > UINT16_MAX ||
        read32(packet) != kTouWireMagic || packet[4] < kTouHello || packet[4] > kTouFec || packet[5] != 0 ||
        (((size_t) packet[6] << 8U) | packet[7]) != size - kTouEnvelopeSize)
    {
        return false;
    }
    *wire = (tou_wire_t) {.kind = packet[4], .body = packet + kTouEnvelopeSize, .body_len = size - kTouEnvelopeSize};
    memoryCopy(wire->client_nonce, packet + 8, kTouNonceSize);
    memoryCopy(wire->server_nonce, packet + 24, kTouNonceSize);
    if (touNonceIsZero(wire->client_nonce) ||
        (wire->kind == kTouHello ? ! touNonceIsZero(wire->server_nonce) : touNonceIsZero(wire->server_nonce)))
    {
        return false;
    }
    if (wire->kind <= kTouReady)
    {
        tou_settings_t settings;
        return touSettingsDecode(wire->body, wire->body_len, &settings);
    }
    return wire->body_len > 0;
}

bool touWireEncode(uint8_t *packet, size_t capacity, uint8_t kind, const uint8_t client[kTouNonceSize],
                   const uint8_t server[kTouNonceSize], const uint8_t *body, size_t body_len)
{
    if (body_len > UINT16_MAX || capacity < body_len + kTouEnvelopeSize)
    {
        return false;
    }
    uint8_t *p = packet;
    write32(p, kTouWireMagic);
    p[4] = kind;
    p[5] = 0;
    p[6] = (uint8_t) (body_len >> 8U);
    p[7] = (uint8_t) body_len;
    memoryCopy(p + 8, client, kTouNonceSize);
    memoryCopy(p + 24, server, kTouNonceSize);
    if (body_len != 0)
    {
        memoryCopyLarge(p + kTouEnvelopeSize, body, body_len);
    }
    return true;
}

sbuf_t *touWireCreate(buffer_pool_t *pool, uint8_t kind, const uint8_t client[kTouNonceSize],
                      const uint8_t server[kTouNonceSize], const uint8_t *body, size_t body_len)
{
    if (body_len > UINT16_MAX)
    {
        return NULL;
    }
    const size_t size = body_len + kTouEnvelopeSize;
    sbuf_t      *buf  = bufferpoolTryGetBestFit(pool, size, 0);
    if (buf == NULL)
    {
        return NULL;
    }
    sbufSetLength(buf, (uint32_t) size);
    const bool encoded = touWireEncode(sbufGetMutablePtr(buf), size, kind, client, server, body, body_len);
    assert(encoded);
    discard encoded;
    return buf;
}

sbuf_t *touControlCreate(buffer_pool_t *pool, uint8_t kind, const uint8_t client[kTouNonceSize],
                         const uint8_t server[kTouNonceSize], const tou_settings_t *settings)
{
    uint8_t body[kTouSettingsSize];
    touSettingsEncode(body, settings);
    return touWireCreate(pool, kind, client, server, body, sizeof(body));
}
