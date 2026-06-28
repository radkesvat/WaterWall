#include "ipsec_natt.h"

enum
{
    kIpsecNattNonEspMarkerLen = 4,
    kIpsecNattIkev2HeaderLen  = 28,
    kIpsecNattEspHeaderLen    = 8,

    kIkev2PayloadNone     = 0,
    kIkev2PayloadSa       = 33,
    kIkev2PayloadKe       = 34,
    kIkev2PayloadNonce    = 40,
    kIkev2PayloadNotify   = 41,
    kIkev2PayloadVendorId = 43,
    kIkev2PayloadSk       = 46,

    kIkev2ExchangeSaInit        = 34,
    kIkev2ExchangeInformational = 37,
    kIkev2Version               = 0x20,
    kIkev2FlagInitiator         = 0x08,

    kIkev2ProtocolIke                    = 1,
    kIkev2TransformTypeEncr              = 1,
    kIkev2TransformTypePrf               = 2,
    kIkev2TransformTypeInteg             = 3,
    kIkev2TransformTypeDh                = 4,
    kIkev2TransformEncrAesCbc            = 12,
    kIkev2TransformPrfHmacSha2_256       = 5,
    kIkev2TransformIntegHmacSha2_256_128 = 12,
    kIkev2TransformDhGroupEcp256         = 19,
    kIkev2TransformAttrKeyLength         = 14,

    kIkev2NotifyNatDetectionSourceIp      = 16388,
    kIkev2NotifyNatDetectionDestinationIp = 16389,
};

typedef struct junkdatagramsender_ipsec_writer_s
{
    sbuf_t  *buf;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_ipsec_writer_t;

static uint32_t junkdatagramsenderIpsecWriteLimit(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t limit = sbufGetMaximumWriteableSize(buf);
    if (args != NULL && args->max_packet_size > 0 && args->max_packet_size < limit)
    {
        limit = args->max_packet_size;
    }
    return limit;
}

static bool junkdatagramsenderIpsecCanWrite(const junkdatagramsender_ipsec_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderIpsecPutBytes(junkdatagramsender_ipsec_writer_t *writer, const void *src, uint32_t len)
{
    if (! junkdatagramsenderIpsecCanWrite(writer, len) || (len > 0 && src == NULL))
    {
        return false;
    }

    if (len > 0)
    {
        memoryCopy(sbufGetMutablePtr(writer->buf) + writer->pos, src, len);
    }
    writer->pos += len;
    return true;
}

static bool junkdatagramsenderIpsecPutRandom(junkdatagramsender_ipsec_writer_t *writer, uint32_t len)
{
    if (! junkdatagramsenderIpsecCanWrite(writer, len))
    {
        return false;
    }

    if (len > 0)
    {
        getRandomBytes(sbufGetMutablePtr(writer->buf) + writer->pos, len);
    }
    writer->pos += len;
    return true;
}

static bool junkdatagramsenderIpsecPutU8(junkdatagramsender_ipsec_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderIpsecPutBytes(writer, &value, sizeof(value));
}

static bool junkdatagramsenderIpsecPutU16(junkdatagramsender_ipsec_writer_t *writer, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderIpsecPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderIpsecPutU32(junkdatagramsender_ipsec_writer_t *writer, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderIpsecPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderIpsecPutU64(junkdatagramsender_ipsec_writer_t *writer, uint64_t value)
{
    uint64_t network_value = htobe64(value);
    return junkdatagramsenderIpsecPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderIpsecPatchU16(junkdatagramsender_ipsec_writer_t *writer, uint32_t offset, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    if (offset > writer->pos || sizeof(network_value) > writer->pos - offset)
    {
        return false;
    }

    memoryCopy(sbufGetMutablePtr(writer->buf) + offset, &network_value, sizeof(network_value));
    return true;
}

static bool junkdatagramsenderIpsecPatchU32(junkdatagramsender_ipsec_writer_t *writer, uint32_t offset, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    if (offset > writer->pos || sizeof(network_value) > writer->pos - offset)
    {
        return false;
    }

    memoryCopy(sbufGetMutablePtr(writer->buf) + offset, &network_value, sizeof(network_value));
    return true;
}

static uint32_t junkdatagramsenderIpsecRandomNonZeroU32(void)
{
    uint32_t value = fastRand32();
    return value == 0 ? 1 : value;
}

static bool junkdatagramsenderIpsecBeginPayload(junkdatagramsender_ipsec_writer_t *writer, uint8_t next_payload,
                                                uint32_t *length_offset, uint32_t *body_offset)
{
    if (! junkdatagramsenderIpsecPutU8(writer, next_payload) || ! junkdatagramsenderIpsecPutU8(writer, 0))
    {
        return false;
    }

    *length_offset = writer->pos;
    if (! junkdatagramsenderIpsecPutU16(writer, 0))
    {
        return false;
    }

    *body_offset = writer->pos;
    return true;
}

static bool junkdatagramsenderIpsecEndPayload(junkdatagramsender_ipsec_writer_t *writer, uint32_t length_offset,
                                              uint32_t payload_start)
{
    uint32_t payload_len = writer->pos - payload_start;
    if (payload_len > UINT16_MAX)
    {
        return false;
    }
    return junkdatagramsenderIpsecPatchU16(writer, length_offset, (uint16_t) payload_len);
}

static bool junkdatagramsenderIpsecPutTransform(junkdatagramsender_ipsec_writer_t *writer, uint8_t next_transform,
                                                uint8_t transform_type, uint16_t transform_id, bool add_key_length)
{
    uint32_t transform_start = writer->pos;
    uint16_t transform_len   = add_key_length ? 12 : 8;

    if (! junkdatagramsenderIpsecPutU8(writer, next_transform) || ! junkdatagramsenderIpsecPutU8(writer, 0) ||
        ! junkdatagramsenderIpsecPutU16(writer, transform_len) ||
        ! junkdatagramsenderIpsecPutU8(writer, transform_type) || ! junkdatagramsenderIpsecPutU8(writer, 0) ||
        ! junkdatagramsenderIpsecPutU16(writer, transform_id))
    {
        return false;
    }

    if (add_key_length && (! junkdatagramsenderIpsecPutU16(writer, UINT16_C(0x8000) | kIkev2TransformAttrKeyLength) ||
                           ! junkdatagramsenderIpsecPutU16(writer, 128)))
    {
        return false;
    }

    return writer->pos - transform_start == transform_len;
}

static bool junkdatagramsenderIpsecPutSaPayloadBody(junkdatagramsender_ipsec_writer_t *writer)
{
    uint32_t proposal_start      = writer->pos;
    uint32_t proposal_len_offset = 0;

    if (! junkdatagramsenderIpsecPutU8(writer, 0) || ! junkdatagramsenderIpsecPutU8(writer, 0))
    {
        return false;
    }

    proposal_len_offset = writer->pos;
    if (! junkdatagramsenderIpsecPutU16(writer, 0) || ! junkdatagramsenderIpsecPutU8(writer, 1) ||
        ! junkdatagramsenderIpsecPutU8(writer, kIkev2ProtocolIke) || ! junkdatagramsenderIpsecPutU8(writer, 0) ||
        ! junkdatagramsenderIpsecPutU8(writer, 4))
    {
        return false;
    }

    if (! junkdatagramsenderIpsecPutTransform(writer, 3, kIkev2TransformTypeEncr, kIkev2TransformEncrAesCbc, true) ||
        ! junkdatagramsenderIpsecPutTransform(
            writer, 3, kIkev2TransformTypePrf, kIkev2TransformPrfHmacSha2_256, false) ||
        ! junkdatagramsenderIpsecPutTransform(
            writer, 3, kIkev2TransformTypeInteg, kIkev2TransformIntegHmacSha2_256_128, false) ||
        ! junkdatagramsenderIpsecPutTransform(writer, 0, kIkev2TransformTypeDh, kIkev2TransformDhGroupEcp256, false))
    {
        return false;
    }

    return junkdatagramsenderIpsecPatchU16(writer, proposal_len_offset, (uint16_t) (writer->pos - proposal_start));
}

static bool junkdatagramsenderIpsecPutKePayloadBody(junkdatagramsender_ipsec_writer_t *writer)
{
    return junkdatagramsenderIpsecPutU16(writer, kIkev2TransformDhGroupEcp256) &&
           junkdatagramsenderIpsecPutU16(writer, 0) && junkdatagramsenderIpsecPutRandom(writer, 64);
}

static bool junkdatagramsenderIpsecPutNoncePayloadBody(junkdatagramsender_ipsec_writer_t *writer)
{
    return junkdatagramsenderIpsecPutRandom(writer, fastRandRange32(20, 32));
}

static bool junkdatagramsenderIpsecPutNotifyPayloadBody(junkdatagramsender_ipsec_writer_t *writer, uint16_t notify_type)
{
    return junkdatagramsenderIpsecPutU8(writer, kIkev2ProtocolIke) && junkdatagramsenderIpsecPutU8(writer, 0) &&
           junkdatagramsenderIpsecPutU16(writer, notify_type) && junkdatagramsenderIpsecPutRandom(writer, 20);
}

static bool junkdatagramsenderIpsecPutVendorIdPayloadBody(junkdatagramsender_ipsec_writer_t *writer)
{
    static const uint8_t vendor_id[] = {
        's',
        't',
        'r',
        'o',
        'n',
        'g',
        'S',
        'w',
        'a',
        'n',
    };

    if ((fastRand32() % 100U) < 60U)
    {
        return junkdatagramsenderIpsecPutBytes(writer, vendor_id, sizeof(vendor_id));
    }
    return junkdatagramsenderIpsecPutRandom(writer, 16);
}

static bool junkdatagramsenderIpsecPutPayload(junkdatagramsender_ipsec_writer_t *writer, uint8_t next_payload,
                                              bool (*put_body)(junkdatagramsender_ipsec_writer_t *writer))
{
    uint32_t payload_start = writer->pos;
    uint32_t length_offset = 0;
    uint32_t body_offset   = 0;

    discard body_offset;

    if (! junkdatagramsenderIpsecBeginPayload(writer, next_payload, &length_offset, &body_offset) || ! put_body(writer))
    {
        return false;
    }

    return junkdatagramsenderIpsecEndPayload(writer, length_offset, payload_start);
}

static bool junkdatagramsenderIpsecPutNatSourceNotify(junkdatagramsender_ipsec_writer_t *writer)
{
    return junkdatagramsenderIpsecPutNotifyPayloadBody(writer, kIkev2NotifyNatDetectionSourceIp);
}

static bool junkdatagramsenderIpsecPutNatDestinationNotify(junkdatagramsender_ipsec_writer_t *writer)
{
    return junkdatagramsenderIpsecPutNotifyPayloadBody(writer, kIkev2NotifyNatDetectionDestinationIp);
}

static bool junkdatagramsenderIpsecBuildIkev2Header(junkdatagramsender_ipsec_writer_t *writer, uint8_t first_payload,
                                                    uint8_t exchange_type, uint32_t message_id, uint32_t *length_offset,
                                                    bool responder_spi)
{
    uint64_t initiator_spi = (((uint64_t) fastRand32()) << 32U) | fastRand32();
    uint64_t response_spi  = responder_spi ? ((((uint64_t) fastRand32()) << 32U) | fastRand32()) : 0;

    if (initiator_spi == 0)
    {
        initiator_spi = 1;
    }
    if (responder_spi && response_spi == 0)
    {
        response_spi = 1;
    }

    if (! junkdatagramsenderIpsecPutU64(writer, initiator_spi) ||
        ! junkdatagramsenderIpsecPutU64(writer, response_spi) ||
        ! junkdatagramsenderIpsecPutU8(writer, first_payload) ||
        ! junkdatagramsenderIpsecPutU8(writer, kIkev2Version) ||
        ! junkdatagramsenderIpsecPutU8(writer, exchange_type) ||
        ! junkdatagramsenderIpsecPutU8(writer, kIkev2FlagInitiator) ||
        ! junkdatagramsenderIpsecPutU32(writer, message_id))
    {
        return false;
    }

    *length_offset = writer->pos;
    return junkdatagramsenderIpsecPutU32(writer, 0);
}

static bool junkdatagramsenderIpsecFinishIkev2Message(junkdatagramsender_ipsec_writer_t *writer, uint32_t ike_start,
                                                      uint32_t length_offset)
{
    uint32_t ike_len = writer->pos - ike_start;
    if (! junkdatagramsenderIpsecPatchU32(writer, length_offset, ike_len))
    {
        return false;
    }

    sbufSetLength(writer->buf, writer->pos);
    return true;
}

static bool junkdatagramsenderIpsecBuildIkeSaInit(sbuf_t *buf, uint32_t write_limit)
{
    junkdatagramsender_ipsec_writer_t writer        = {.buf = buf, .pos = 0, .capacity = write_limit};
    uint32_t                          ike_start     = kIpsecNattNonEspMarkerLen;
    uint32_t                          length_offset = 0;

    if (! junkdatagramsenderIpsecPutU32(&writer, 0) ||
        ! junkdatagramsenderIpsecBuildIkev2Header(
            &writer, kIkev2PayloadSa, kIkev2ExchangeSaInit, 0, &length_offset, false) ||
        ! junkdatagramsenderIpsecPutPayload(&writer, kIkev2PayloadKe, junkdatagramsenderIpsecPutSaPayloadBody) ||
        ! junkdatagramsenderIpsecPutPayload(&writer, kIkev2PayloadNonce, junkdatagramsenderIpsecPutKePayloadBody) ||
        ! junkdatagramsenderIpsecPutPayload(&writer, kIkev2PayloadNotify, junkdatagramsenderIpsecPutNoncePayloadBody) ||
        ! junkdatagramsenderIpsecPutPayload(&writer, kIkev2PayloadNotify, junkdatagramsenderIpsecPutNatSourceNotify) ||
        ! junkdatagramsenderIpsecPutPayload(
            &writer, kIkev2PayloadVendorId, junkdatagramsenderIpsecPutNatDestinationNotify) ||
        ! junkdatagramsenderIpsecPutPayload(&writer, kIkev2PayloadNone, junkdatagramsenderIpsecPutVendorIdPayloadBody))
    {
        return false;
    }

    return junkdatagramsenderIpsecFinishIkev2Message(&writer, ike_start, length_offset);
}

static bool junkdatagramsenderIpsecPutEncryptedPayloadBody(junkdatagramsender_ipsec_writer_t *writer)
{
    return junkdatagramsenderIpsecPutRandom(writer, fastRandRange32(48, 192));
}

static bool junkdatagramsenderIpsecBuildIkeInformational(sbuf_t *buf, uint32_t write_limit)
{
    junkdatagramsender_ipsec_writer_t writer        = {.buf = buf, .pos = 0, .capacity = write_limit};
    uint32_t                          ike_start     = kIpsecNattNonEspMarkerLen;
    uint32_t                          length_offset = 0;

    if (! junkdatagramsenderIpsecPutU32(&writer, 0) ||
        ! junkdatagramsenderIpsecBuildIkev2Header(&writer,
                                                  kIkev2PayloadSk,
                                                  kIkev2ExchangeInformational,
                                                  fastRandRange32(1, 32),
                                                  &length_offset,
                                                  true) ||
        ! junkdatagramsenderIpsecPutPayload(&writer, kIkev2PayloadNone, junkdatagramsenderIpsecPutEncryptedPayloadBody))
    {
        return false;
    }

    return junkdatagramsenderIpsecFinishIkev2Message(&writer, ike_start, length_offset);
}

static bool junkdatagramsenderIpsecBuildEspInUdp(sbuf_t *buf, uint32_t write_limit)
{
    junkdatagramsender_ipsec_writer_t writer        = {.buf = buf, .pos = 0, .capacity = write_limit};
    uint32_t                          encrypted_len = fastRandRange32(24, 192);

    if (! junkdatagramsenderIpsecPutU32(&writer, junkdatagramsenderIpsecRandomNonZeroU32()) ||
        ! junkdatagramsenderIpsecPutU32(&writer, fastRandRange32(1, 65535)) ||
        ! junkdatagramsenderIpsecPutRandom(&writer, encrypted_len))
    {
        return false;
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderIpsecBuildKeepalive(sbuf_t *buf, uint32_t write_limit)
{
    junkdatagramsender_ipsec_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};

    if (! junkdatagramsenderIpsecPutU8(&writer, 0xFF))
    {
        return false;
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

bool junkdatagramsenderIpsecNattGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    typedef bool (*generator_fn)(sbuf_t *buf, uint32_t write_limit);

    static const generator_fn generators[] = {
        junkdatagramsenderIpsecBuildIkeSaInit,
        junkdatagramsenderIpsecBuildIkeInformational,
        junkdatagramsenderIpsecBuildEspInUdp,
        junkdatagramsenderIpsecBuildKeepalive,
    };

    uint32_t write_limit = junkdatagramsenderIpsecWriteLimit(buf, args);
    if (write_limit == 0)
    {
        return false;
    }

    uint32_t first = fastRand32() % (sizeof(generators) / sizeof(generators[0]));
    for (uint32_t i = 0; i < (uint32_t) (sizeof(generators) / sizeof(generators[0])); ++i)
    {
        generator_fn generate = generators[(first + i) % (sizeof(generators) / sizeof(generators[0]))];
        sbufSetLength(buf, 0);
        if (generate(buf, write_limit) && sbufGetLength(buf) > 0)
        {
            return true;
        }
    }

    return false;
}
