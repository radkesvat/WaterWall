#include "snmp.h"

enum
{
    kSnmpVersion1  = 0,
    kSnmpVersion2c = 1,

    kSnmpPduGet     = 0xA0,
    kSnmpPduGetNext = 0xA1,
    kSnmpPduGetBulk = 0xA5,

    kSnmpBerSequence    = 0x30,
    kSnmpBerInteger     = 0x02,
    kSnmpBerOctetString = 0x04,
    kSnmpBerNull        = 0x05,
    kSnmpBerObjectId    = 0x06,
};

typedef struct junkdatagramsender_snmp_writer_s
{
    sbuf_t  *buf;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_snmp_writer_t;

static uint32_t junkdatagramsenderSnmpWriteLimit(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t limit = sbufGetMaximumWriteableSize(buf);
    if (args != NULL && args->max_packet_size > 0 && args->max_packet_size < limit)
    {
        limit = args->max_packet_size;
    }
    return limit;
}

static bool junkdatagramsenderSnmpCanWrite(const junkdatagramsender_snmp_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderSnmpPutBytes(junkdatagramsender_snmp_writer_t *writer, const void *src, uint32_t len)
{
    if (! junkdatagramsenderSnmpCanWrite(writer, len) || (len > 0 && src == NULL))
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

static bool junkdatagramsenderSnmpPutU8(junkdatagramsender_snmp_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderSnmpPutBytes(writer, &value, sizeof(value));
}

static size_t junkdatagramsenderSnmpBerLenSize(size_t len)
{
    if (len < 128U)
    {
        return 1;
    }
    if (len <= UINT8_MAX)
    {
        return 2;
    }
    if (len <= UINT16_MAX)
    {
        return 3;
    }
    if (len <= 0xFFFFFFU)
    {
        return 4;
    }
    if (len <= UINT32_MAX)
    {
        return 5;
    }
    return 0;
}

static bool junkdatagramsenderSnmpPutBerLen(junkdatagramsender_snmp_writer_t *writer, size_t len)
{
    if (len < 128U)
    {
        return junkdatagramsenderSnmpPutU8(writer, (uint8_t) len);
    }
    if (len <= UINT8_MAX)
    {
        return junkdatagramsenderSnmpPutU8(writer, 0x81) && junkdatagramsenderSnmpPutU8(writer, (uint8_t) len);
    }
    if (len <= UINT16_MAX)
    {
        return junkdatagramsenderSnmpPutU8(writer, 0x82) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((len >> 8U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) (len & 0xFFU));
    }
    if (len <= 0xFFFFFFU)
    {
        return junkdatagramsenderSnmpPutU8(writer, 0x83) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((len >> 16U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((len >> 8U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) (len & 0xFFU));
    }
    if (len <= UINT32_MAX)
    {
        return junkdatagramsenderSnmpPutU8(writer, 0x84) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((len >> 24U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((len >> 16U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((len >> 8U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) (len & 0xFFU));
    }
    return false;
}

static bool junkdatagramsenderSnmpPutTlvHeader(junkdatagramsender_snmp_writer_t *writer, uint8_t tag, size_t len)
{
    return junkdatagramsenderSnmpBerLenSize(len) != 0 && junkdatagramsenderSnmpPutU8(writer, tag) &&
           junkdatagramsenderSnmpPutBerLen(writer, len);
}

static size_t junkdatagramsenderSnmpBerTlvSize(size_t value_len)
{
    size_t len_size = junkdatagramsenderSnmpBerLenSize(value_len);
    return len_size == 0 ? 0 : 1U + len_size + value_len;
}

static size_t junkdatagramsenderSnmpU32IntValueLen(uint32_t value)
{
    if (value <= 0x7FU)
    {
        return 1;
    }
    if (value <= 0x7FFFU)
    {
        return 2;
    }
    if (value <= 0x7FFFFFU)
    {
        return 3;
    }
    if (value <= 0x7FFFFFFFU)
    {
        return 4;
    }
    return 5;
}

static bool junkdatagramsenderSnmpPutIntegerU32(junkdatagramsender_snmp_writer_t *writer, uint32_t value)
{
    size_t len = junkdatagramsenderSnmpU32IntValueLen(value);

    if (! junkdatagramsenderSnmpPutTlvHeader(writer, kSnmpBerInteger, len))
    {
        return false;
    }

    if (len == 5)
    {
        return junkdatagramsenderSnmpPutU8(writer, 0) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((value >> 24U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((value >> 16U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((value >> 8U) & 0xFFU)) &&
               junkdatagramsenderSnmpPutU8(writer, (uint8_t) (value & 0xFFU));
    }

    for (size_t remaining = len; remaining > 0; --remaining)
    {
        if (! junkdatagramsenderSnmpPutU8(writer, (uint8_t) ((value >> (8U * (uint32_t) (remaining - 1U))) & 0xFFU)))
        {
            return false;
        }
    }
    return true;
}

static bool junkdatagramsenderSnmpParseOidArc(const char **p, uint32_t *arc)
{
    uint64_t    value      = 0;
    bool        have_digit = false;
    const char *s          = *p;

    while (*s >= '0' && *s <= '9')
    {
        have_digit = true;
        value      = value * 10U + (uint32_t) (*s - '0');
        if (value > UINT32_MAX)
        {
            return false;
        }
        ++s;
    }

    if (! have_digit)
    {
        return false;
    }

    *arc = (uint32_t) value;
    *p   = s;
    return true;
}

static size_t junkdatagramsenderSnmpOidSubidLen(uint64_t subid)
{
    size_t len = 1;
    while (subid >= 128U)
    {
        subid >>= 7U;
        ++len;
    }
    return len;
}

static bool junkdatagramsenderSnmpPutOidSubid(junkdatagramsender_snmp_writer_t *writer, uint64_t subid)
{
    uint8_t tmp[10];
    size_t  n = 0;

    tmp[n++] = (uint8_t) (subid & 0x7FU);
    subid >>= 7U;

    while (subid != 0)
    {
        tmp[n++] = (uint8_t) (0x80U | (subid & 0x7FU));
        subid >>= 7U;
    }

    while (n > 0)
    {
        if (! junkdatagramsenderSnmpPutU8(writer, tmp[--n]))
        {
            return false;
        }
    }
    return true;
}

static bool junkdatagramsenderSnmpOidValueLen(const char *oid, size_t *value_len)
{
    const char *p    = oid;
    uint32_t    arc0 = 0;
    uint32_t    arc1 = 0;
    size_t      len  = 0;

    if (oid == NULL || value_len == NULL)
    {
        return false;
    }

    if (*p == '.')
    {
        ++p;
    }

    if (! junkdatagramsenderSnmpParseOidArc(&p, &arc0) || *p != '.')
    {
        return false;
    }
    ++p;

    if (! junkdatagramsenderSnmpParseOidArc(&p, &arc1) || arc0 > 2 || (arc0 < 2 && arc1 > 39))
    {
        return false;
    }

    len += junkdatagramsenderSnmpOidSubidLen((uint64_t) arc0 * 40U + arc1);

    while (*p != '\0')
    {
        uint32_t arc = 0;
        if (*p != '.')
        {
            return false;
        }
        ++p;
        if (! junkdatagramsenderSnmpParseOidArc(&p, &arc))
        {
            return false;
        }
        len += junkdatagramsenderSnmpOidSubidLen(arc);
    }

    *value_len = len;
    return true;
}

static bool junkdatagramsenderSnmpPutOidValue(junkdatagramsender_snmp_writer_t *writer, const char *oid)
{
    const char *p    = oid;
    uint32_t    arc0 = 0;
    uint32_t    arc1 = 0;

    if (oid == NULL)
    {
        return false;
    }
    if (*p == '.')
    {
        ++p;
    }

    if (! junkdatagramsenderSnmpParseOidArc(&p, &arc0) || *p != '.')
    {
        return false;
    }
    ++p;

    if (! junkdatagramsenderSnmpParseOidArc(&p, &arc1) || arc0 > 2 || (arc0 < 2 && arc1 > 39) ||
        ! junkdatagramsenderSnmpPutOidSubid(writer, (uint64_t) arc0 * 40U + arc1))
    {
        return false;
    }

    while (*p != '\0')
    {
        uint32_t arc = 0;
        if (*p != '.')
        {
            return false;
        }
        ++p;
        if (! junkdatagramsenderSnmpParseOidArc(&p, &arc) || ! junkdatagramsenderSnmpPutOidSubid(writer, arc))
        {
            return false;
        }
    }
    return true;
}

static bool junkdatagramsenderSnmpPutOidTlv(junkdatagramsender_snmp_writer_t *writer, const char *oid)
{
    size_t oid_len = 0;

    return junkdatagramsenderSnmpOidValueLen(oid, &oid_len) &&
           junkdatagramsenderSnmpPutTlvHeader(writer, kSnmpBerObjectId, oid_len) &&
           junkdatagramsenderSnmpPutOidValue(writer, oid);
}

static bool junkdatagramsenderSnmpPutNullTlv(junkdatagramsender_snmp_writer_t *writer)
{
    return junkdatagramsenderSnmpPutU8(writer, kSnmpBerNull) && junkdatagramsenderSnmpPutU8(writer, 0);
}

static bool junkdatagramsenderSnmpBuildV1V2cNullRequest(sbuf_t *buf, uint32_t write_limit, uint8_t snmp_version,
                                                        const char *community, uint8_t pdu_tag, uint32_t request_id,
                                                        uint32_t pdu_integer_2, uint32_t pdu_integer_3,
                                                        const char *const *oid_list, size_t oid_count)
{
    junkdatagramsender_snmp_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = write_limit,
    };

    if (community == NULL || oid_list == NULL || oid_count == 0 ||
        (snmp_version != kSnmpVersion1 && snmp_version != kSnmpVersion2c) ||
        (pdu_tag != kSnmpPduGet && pdu_tag != kSnmpPduGetNext && pdu_tag != kSnmpPduGetBulk) ||
        (pdu_tag == kSnmpPduGetBulk && snmp_version != kSnmpVersion2c))
    {
        return false;
    }

    size_t community_len            = stringLength(community);
    size_t varbind_list_content_len = 0;

    for (size_t i = 0; i < oid_count; ++i)
    {
        size_t oid_value_len = 0;
        if (! junkdatagramsenderSnmpOidValueLen(oid_list[i], &oid_value_len))
        {
            return false;
        }

        size_t oid_tlv_len         = junkdatagramsenderSnmpBerTlvSize(oid_value_len);
        size_t varbind_content_len = oid_tlv_len + 2U;
        size_t varbind_tlv_len     = junkdatagramsenderSnmpBerTlvSize(varbind_content_len);
        if (oid_tlv_len == 0 || varbind_tlv_len == 0)
        {
            return false;
        }
        varbind_list_content_len += varbind_tlv_len;
    }

    size_t varbind_list_tlv_len = junkdatagramsenderSnmpBerTlvSize(varbind_list_content_len);
    if (varbind_list_tlv_len == 0)
    {
        return false;
    }

    size_t pdu_content_len = junkdatagramsenderSnmpBerTlvSize(junkdatagramsenderSnmpU32IntValueLen(request_id)) +
                             junkdatagramsenderSnmpBerTlvSize(junkdatagramsenderSnmpU32IntValueLen(pdu_integer_2)) +
                             junkdatagramsenderSnmpBerTlvSize(junkdatagramsenderSnmpU32IntValueLen(pdu_integer_3)) +
                             varbind_list_tlv_len;
    size_t pdu_tlv_len     = junkdatagramsenderSnmpBerTlvSize(pdu_content_len);
    size_t msg_content_len = junkdatagramsenderSnmpBerTlvSize(junkdatagramsenderSnmpU32IntValueLen(snmp_version)) +
                             junkdatagramsenderSnmpBerTlvSize(community_len) + pdu_tlv_len;

    if (pdu_tlv_len == 0 || ! junkdatagramsenderSnmpPutTlvHeader(&writer, kSnmpBerSequence, msg_content_len) ||
        ! junkdatagramsenderSnmpPutIntegerU32(&writer, snmp_version) ||
        ! junkdatagramsenderSnmpPutTlvHeader(&writer, kSnmpBerOctetString, community_len) ||
        ! junkdatagramsenderSnmpPutBytes(&writer, community, (uint32_t) community_len) ||
        ! junkdatagramsenderSnmpPutTlvHeader(&writer, pdu_tag, pdu_content_len) ||
        ! junkdatagramsenderSnmpPutIntegerU32(&writer, request_id) ||
        ! junkdatagramsenderSnmpPutIntegerU32(&writer, pdu_integer_2) ||
        ! junkdatagramsenderSnmpPutIntegerU32(&writer, pdu_integer_3) ||
        ! junkdatagramsenderSnmpPutTlvHeader(&writer, kSnmpBerSequence, varbind_list_content_len))
    {
        return false;
    }

    for (size_t i = 0; i < oid_count; ++i)
    {
        size_t oid_value_len = 0;
        if (! junkdatagramsenderSnmpOidValueLen(oid_list[i], &oid_value_len))
        {
            return false;
        }

        size_t varbind_content_len = junkdatagramsenderSnmpBerTlvSize(oid_value_len) + 2U;
        if (! junkdatagramsenderSnmpPutTlvHeader(&writer, kSnmpBerSequence, varbind_content_len) ||
            ! junkdatagramsenderSnmpPutOidTlv(&writer, oid_list[i]) || ! junkdatagramsenderSnmpPutNullTlv(&writer))
        {
            return false;
        }
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static const char *junkdatagramsenderSnmpRandomCommunity(void)
{
    static const char *communities[] = {
        "public",
        "public",
        "private",
        "monitor",
        "readonly",
        "snmp",
    };

    return communities[fastRand32() % (sizeof(communities) / sizeof(communities[0]))];
}

static const char *junkdatagramsenderSnmpRandomOid(void)
{
    static const char *oids[] = {
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.2.1.1.5.0",
        "1.3.6.1.2.1.1.6.0",
        "1.3.6.1.2.1.2.1.0",
        "1.3.6.1.2.1.2.2.1.2.1",
        "1.3.6.1.2.1.2.2.1.8.1",
        "1.3.6.1.2.1.25.1.1.0",
        "1.3.6.1.2.1.31.1.1.1.1.1",
        "1.3.6.1.4.1.2021.10.1.3.1",
    };

    return oids[fastRand32() % (sizeof(oids) / sizeof(oids[0]))];
}

bool junkdatagramsenderSnmpGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    const char *oid_list[4];
    uint32_t    write_limit = junkdatagramsenderSnmpWriteLimit(buf, args);
    if (write_limit == 0)
    {
        return false;
    }

    size_t oid_count = 1U + (fastRand32() % (sizeof(oid_list) / sizeof(oid_list[0])));
    for (size_t i = 0; i < oid_count; ++i)
    {
        oid_list[i] = junkdatagramsenderSnmpRandomOid();
    }

    uint8_t version = (fastRand32() % 100U) < 80U ? kSnmpVersion2c : kSnmpVersion1;
    uint8_t pdu_tag = kSnmpPduGet;

    switch (fastRand32() % 3U)
    {
    case 0:
        pdu_tag = kSnmpPduGet;
        break;
    case 1:
        pdu_tag = kSnmpPduGetNext;
        break;
    default:
        if (version == kSnmpVersion2c)
        {
            pdu_tag = kSnmpPduGetBulk;
        }
        else
        {
            pdu_tag = kSnmpPduGetNext;
        }
        break;
    }

    sbufSetLength(buf, 0);
    return junkdatagramsenderSnmpBuildV1V2cNullRequest(buf,
                                                       write_limit,
                                                       version,
                                                       junkdatagramsenderSnmpRandomCommunity(),
                                                       pdu_tag,
                                                       fastRand32() & 0x7FFFFFFFU,
                                                       pdu_tag == kSnmpPduGetBulk ? (fastRand32() % 2U) : 0,
                                                       pdu_tag == kSnmpPduGetBulk ? (3U + (fastRand32() % 18U)) : 0,
                                                       oid_list,
                                                       oid_count);
}
