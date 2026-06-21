#include "rtp_rtcp_srtp.h"

enum
{
    kRtpVersion               = 2,
    kRtpHeaderLen             = 12,
    kRtpMaxCsrcCount          = 15,
    kRtpPayloadTypeMax        = 127,
    kRtpExtensionProfileOneByte = 0xBEDE,
    kRtpExtensionProfileTwoByte = 0x1000,

    kRtcpVersion              = 2,
    kRtcpPtSenderReport       = 200,
    kRtcpPtReceiverReport     = 201,
    kRtcpPtSdes               = 202,
    kRtcpPtBye                = 203,
    kRtcpSdesEnd              = 0,
    kRtcpSdesCname            = 1,
    kRtcpReportBlockLen       = 24,

    kSrtpAuthTagShortLen      = 4,
    kSrtpAuthTagDefaultLen    = 10,
    kSrtpAuthTagGcmLen        = 16,
    kSrtpMaxMkiLen            = 4,
};

typedef struct junkdatagramsender_rtp_writer_s
{
    sbuf_t  *buf;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_rtp_writer_t;

typedef struct junkdatagramsender_rtcp_report_block_s
{
    uint32_t ssrc;
    uint8_t  fraction_lost;
    uint32_t cumulative_lost_24bit;
    uint32_t extended_highest_seq;
    uint32_t jitter;
    uint32_t last_sr;
    uint32_t delay_since_last_sr;
} junkdatagramsender_rtcp_report_block_t;

static uint32_t junkdatagramsenderRtpRandomRange(uint32_t min_value, uint32_t max_value)
{
    if (max_value <= min_value)
    {
        return min_value;
    }
    return min_value + (fastRand32() % (max_value - min_value + 1U));
}

static bool junkdatagramsenderRtpFormatFits(int written, size_t buf_len)
{
    return written > 0 && (size_t) written < buf_len;
}

static uint32_t junkdatagramsenderRtpWriteLimit(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t limit = sbufGetMaximumWriteableSize(buf);
    if (args != NULL && args->max_packet_size > 0 && args->max_packet_size < limit)
    {
        limit = args->max_packet_size;
    }
    return limit;
}

static bool junkdatagramsenderRtpCanWrite(const junkdatagramsender_rtp_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderRtpPutBytes(junkdatagramsender_rtp_writer_t *writer, const void *src, uint32_t len)
{
    if (! junkdatagramsenderRtpCanWrite(writer, len))
    {
        return false;
    }

    if (len > 0 && src != NULL)
    {
        memoryCopy(sbufGetMutablePtr(writer->buf) + writer->pos, src, len);
    }
    writer->pos += len;
    return true;
}

static bool junkdatagramsenderRtpPutZeros(junkdatagramsender_rtp_writer_t *writer, uint32_t len)
{
    if (! junkdatagramsenderRtpCanWrite(writer, len))
    {
        return false;
    }

    if (len > 0)
    {
        memorySet(sbufGetMutablePtr(writer->buf) + writer->pos, 0, len);
    }
    writer->pos += len;
    return true;
}

static bool junkdatagramsenderRtpPutU8(junkdatagramsender_rtp_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderRtpPutBytes(writer, &value, sizeof(value));
}

static bool junkdatagramsenderRtpPutU16(junkdatagramsender_rtp_writer_t *writer, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderRtpPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderRtpPutU32(junkdatagramsender_rtp_writer_t *writer, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderRtpPutBytes(writer, &network_value, sizeof(network_value));
}

static uint8_t junkdatagramsenderRtpRandomPayloadType(void)
{
    static const uint8_t payload_types[] = {
        0,   /* PCMU */
        8,   /* PCMA */
        96,
        97,
        98,
        100,
        101,
        111, /* Opus in many WebRTC profiles */
        120,
    };

    return payload_types[fastRand32() % (sizeof(payload_types) / sizeof(payload_types[0]))];
}

static uint8_t junkdatagramsenderRtpRandomCsrcList(uint32_t csrc_list[2])
{
    uint32_t roll = fastRand32() % 100U;
    uint8_t  count = 0;

    if (roll >= 94U)
    {
        count = 2;
    }
    else if (roll >= 84U)
    {
        count = 1;
    }

    for (uint8_t i = 0; i < count; ++i)
    {
        csrc_list[i] = fastRand32();
    }
    return count;
}

static bool junkdatagramsenderRtpRandomExtension(uint8_t extension_data[16], uint32_t *extension_data_len,
                                                 uint16_t *extension_profile)
{
    *extension_data_len = 0;
    *extension_profile  = 0;

    if ((fastRand32() % 100U) >= 16U)
    {
        return false;
    }

    *extension_data_len = 4U * junkdatagramsenderRtpRandomRange(1, 3);
    *extension_profile  = (fastRand32() % 100U) < 75U ? kRtpExtensionProfileOneByte : kRtpExtensionProfileTwoByte;

    memorySet(extension_data, 0, *extension_data_len);
    if (*extension_profile == kRtpExtensionProfileOneByte)
    {
        extension_data[0] = 0x10U;
        extension_data[1] = (uint8_t) fastRand32();
        if (*extension_data_len >= 8)
        {
            extension_data[4] = 0x20U;
            extension_data[5] = (uint8_t) fastRand32();
        }
    }
    else
    {
        getRandomBytes(extension_data, *extension_data_len);
    }

    return true;
}

static uint32_t junkdatagramsenderRtpRandomPayloadLen(uint32_t available)
{
    if (available == 0)
    {
        return 0;
    }
    if (available <= 20)
    {
        return junkdatagramsenderRtpRandomRange(1, available);
    }

    uint32_t max_payload = available > 240U ? 240U : available;
    return junkdatagramsenderRtpRandomRange(20, max_payload);
}

static bool junkdatagramsenderRtpBuildPacket(sbuf_t *buf, uint32_t write_limit, bool padding, bool marker,
                                             uint8_t payload_type, uint16_t sequence_number, uint32_t timestamp,
                                             uint32_t ssrc, const uint32_t *csrc_list, uint8_t csrc_count,
                                             const uint8_t *extension_data, uint32_t extension_data_len,
                                             uint16_t extension_profile, const uint8_t *payload,
                                             uint32_t payload_len, uint8_t padding_count)
{
    junkdatagramsender_rtp_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = write_limit,
    };
    bool has_extension = extension_data_len > 0;

    if (payload_type > kRtpPayloadTypeMax || csrc_count > kRtpMaxCsrcCount ||
        (csrc_count > 0 && csrc_list == NULL) || (payload_len > 0 && payload == NULL) ||
        (has_extension && extension_data == NULL) || (extension_data_len % 4U) != 0 ||
        (padding && padding_count == 0) || (! padding && padding_count != 0))
    {
        return false;
    }

    if (! junkdatagramsenderRtpPutU8(&writer,
                                     (uint8_t) ((kRtpVersion << 6U) | (padding ? 0x20U : 0U) |
                                                (has_extension ? 0x10U : 0U) | (csrc_count & 0x0FU))) ||
        ! junkdatagramsenderRtpPutU8(&writer, (uint8_t) ((marker ? 0x80U : 0U) | payload_type)) ||
        ! junkdatagramsenderRtpPutU16(&writer, sequence_number) ||
        ! junkdatagramsenderRtpPutU32(&writer, timestamp) ||
        ! junkdatagramsenderRtpPutU32(&writer, ssrc))
    {
        return false;
    }

    for (uint8_t i = 0; i < csrc_count; ++i)
    {
        if (! junkdatagramsenderRtpPutU32(&writer, csrc_list[i]))
        {
            return false;
        }
    }

    if (has_extension)
    {
        if (extension_data_len / 4U > UINT16_MAX ||
            ! junkdatagramsenderRtpPutU16(&writer, extension_profile) ||
            ! junkdatagramsenderRtpPutU16(&writer, (uint16_t) (extension_data_len / 4U)) ||
            ! junkdatagramsenderRtpPutBytes(&writer, extension_data, extension_data_len))
        {
            return false;
        }
    }

    if (! junkdatagramsenderRtpPutBytes(&writer, payload, payload_len))
    {
        return false;
    }

    if (padding)
    {
        if (padding_count > 1U && ! junkdatagramsenderRtpPutZeros(&writer, (uint32_t) padding_count - 1U))
        {
            return false;
        }
        if (! junkdatagramsenderRtpPutU8(&writer, padding_count))
        {
            return false;
        }
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderRtcpPutHeader(junkdatagramsender_rtp_writer_t *writer, bool padding, uint8_t count,
                                            uint8_t packet_type, uint16_t length_words_minus_one)
{
    if (count > 31)
    {
        return false;
    }

    return junkdatagramsenderRtpPutU8(writer,
                                      (uint8_t) ((kRtcpVersion << 6U) | (padding ? 0x20U : 0U) |
                                                 (count & 0x1FU))) &&
           junkdatagramsenderRtpPutU8(writer, packet_type) &&
           junkdatagramsenderRtpPutU16(writer, length_words_minus_one);
}

static bool junkdatagramsenderRtcpPutReportBlock(junkdatagramsender_rtp_writer_t *writer,
                                                 const junkdatagramsender_rtcp_report_block_t *report_block)
{
    if (report_block == NULL || report_block->cumulative_lost_24bit > 0x00FFFFFFU)
    {
        return false;
    }

    return junkdatagramsenderRtpPutU32(writer, report_block->ssrc) &&
           junkdatagramsenderRtpPutU8(writer, report_block->fraction_lost) &&
           junkdatagramsenderRtpPutU8(writer, (uint8_t) ((report_block->cumulative_lost_24bit >> 16) & 0xFFU)) &&
           junkdatagramsenderRtpPutU8(writer, (uint8_t) ((report_block->cumulative_lost_24bit >> 8) & 0xFFU)) &&
           junkdatagramsenderRtpPutU8(writer, (uint8_t) (report_block->cumulative_lost_24bit & 0xFFU)) &&
           junkdatagramsenderRtpPutU32(writer, report_block->extended_highest_seq) &&
           junkdatagramsenderRtpPutU32(writer, report_block->jitter) &&
           junkdatagramsenderRtpPutU32(writer, report_block->last_sr) &&
           junkdatagramsenderRtpPutU32(writer, report_block->delay_since_last_sr);
}

static void junkdatagramsenderRtcpRandomReportBlock(junkdatagramsender_rtcp_report_block_t *report_block)
{
    *report_block = (junkdatagramsender_rtcp_report_block_t) {
        .ssrc                 = fastRand32(),
        .fraction_lost        = (uint8_t) ((fastRand32() % 100U) < 85U ? 0U : junkdatagramsenderRtpRandomRange(1, 10)),
        .cumulative_lost_24bit = (fastRand32() % 100U) < 85U ? 0U : junkdatagramsenderRtpRandomRange(1, 2000),
        .extended_highest_seq = fastRand32(),
        .jitter               = junkdatagramsenderRtpRandomRange(0, 4000),
        .last_sr              = (fastRand32() % 100U) < 45U ? 0U : fastRand32(),
        .delay_since_last_sr  = junkdatagramsenderRtpRandomRange(0, 65535),
    };
}

static uint8_t junkdatagramsenderRtcpRandomReportBlockCount(uint32_t write_limit, uint32_t base_len)
{
    uint8_t max_count = 0;
    if (write_limit > base_len)
    {
        max_count = (uint8_t) ((write_limit - base_len) / kRtcpReportBlockLen);
        if (max_count > 2)
        {
            max_count = 2;
        }
    }

    if (max_count == 0 || (fastRand32() % 100U) < 55U)
    {
        return 0;
    }
    return (uint8_t) junkdatagramsenderRtpRandomRange(1, max_count);
}

static bool junkdatagramsenderRtcpBuildReceiverReport(sbuf_t *buf, uint32_t write_limit, uint32_t sender_ssrc,
                                                      const junkdatagramsender_rtcp_report_block_t *report_blocks,
                                                      uint8_t report_block_count)
{
    junkdatagramsender_rtp_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = write_limit,
    };

    if (report_block_count > 31 || (report_block_count > 0 && report_blocks == NULL))
    {
        return false;
    }

    uint32_t total_len = 4U + 4U + (uint32_t) kRtcpReportBlockLen * report_block_count;
    if ((total_len % 4U) != 0 || total_len / 4U == 0 || total_len / 4U > (uint32_t) UINT16_MAX + 1U)
    {
        return false;
    }

    if (! junkdatagramsenderRtcpPutHeader(&writer,
                                          false,
                                          report_block_count,
                                          kRtcpPtReceiverReport,
                                          (uint16_t) (total_len / 4U - 1U)) ||
        ! junkdatagramsenderRtpPutU32(&writer, sender_ssrc))
    {
        return false;
    }

    for (uint8_t i = 0; i < report_block_count; ++i)
    {
        if (! junkdatagramsenderRtcpPutReportBlock(&writer, &report_blocks[i]))
        {
            return false;
        }
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderRtcpBuildSenderReport(sbuf_t *buf, uint32_t write_limit, uint32_t sender_ssrc,
                                                    uint32_t ntp_timestamp_msw, uint32_t ntp_timestamp_lsw,
                                                    uint32_t rtp_timestamp, uint32_t sender_packet_count,
                                                    uint32_t sender_octet_count,
                                                    const junkdatagramsender_rtcp_report_block_t *report_blocks,
                                                    uint8_t report_block_count)
{
    junkdatagramsender_rtp_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = write_limit,
    };

    if (report_block_count > 31 || (report_block_count > 0 && report_blocks == NULL))
    {
        return false;
    }

    uint32_t total_len = 4U + 24U + (uint32_t) kRtcpReportBlockLen * report_block_count;
    if ((total_len % 4U) != 0 || total_len / 4U == 0 || total_len / 4U > (uint32_t) UINT16_MAX + 1U)
    {
        return false;
    }

    if (! junkdatagramsenderRtcpPutHeader(&writer,
                                          false,
                                          report_block_count,
                                          kRtcpPtSenderReport,
                                          (uint16_t) (total_len / 4U - 1U)) ||
        ! junkdatagramsenderRtpPutU32(&writer, sender_ssrc) ||
        ! junkdatagramsenderRtpPutU32(&writer, ntp_timestamp_msw) ||
        ! junkdatagramsenderRtpPutU32(&writer, ntp_timestamp_lsw) ||
        ! junkdatagramsenderRtpPutU32(&writer, rtp_timestamp) ||
        ! junkdatagramsenderRtpPutU32(&writer, sender_packet_count) ||
        ! junkdatagramsenderRtpPutU32(&writer, sender_octet_count))
    {
        return false;
    }

    for (uint8_t i = 0; i < report_block_count; ++i)
    {
        if (! junkdatagramsenderRtcpPutReportBlock(&writer, &report_blocks[i]))
        {
            return false;
        }
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderRtcpBuildSdesCname(sbuf_t *buf, uint32_t write_limit, uint32_t ssrc,
                                                 const char *cname)
{
    junkdatagramsender_rtp_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = write_limit,
    };

    if (cname == NULL)
    {
        return false;
    }

    size_t cname_len = stringLength(cname);
    if (cname_len > UINT8_MAX)
    {
        return false;
    }

    uint32_t chunk_payload_len = 4U + 1U + 1U + (uint32_t) cname_len + 1U;
    uint32_t chunk_padded_len  = (chunk_payload_len + 3U) & ~UINT32_C(3);
    uint32_t total_len         = 4U + chunk_padded_len;
    if (total_len / 4U == 0 || total_len / 4U > (uint32_t) UINT16_MAX + 1U)
    {
        return false;
    }

    if (! junkdatagramsenderRtcpPutHeader(&writer,
                                          false,
                                          1,
                                          kRtcpPtSdes,
                                          (uint16_t) (total_len / 4U - 1U)) ||
        ! junkdatagramsenderRtpPutU32(&writer, ssrc) ||
        ! junkdatagramsenderRtpPutU8(&writer, kRtcpSdesCname) ||
        ! junkdatagramsenderRtpPutU8(&writer, (uint8_t) cname_len) ||
        ! junkdatagramsenderRtpPutBytes(&writer, cname, (uint32_t) cname_len) ||
        ! junkdatagramsenderRtpPutU8(&writer, kRtcpSdesEnd))
    {
        return false;
    }

    while (writer.pos < total_len)
    {
        if (! junkdatagramsenderRtpPutU8(&writer, 0))
        {
            return false;
        }
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderRtcpBuildBye(sbuf_t *buf, uint32_t write_limit, const uint32_t *ssrc_list,
                                           uint8_t ssrc_count, const char *reason)
{
    junkdatagramsender_rtp_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = write_limit,
    };

    if (ssrc_count == 0 || ssrc_count > 31 || ssrc_list == NULL)
    {
        return false;
    }

    size_t reason_len = reason != NULL ? stringLength(reason) : 0;
    if (reason_len > UINT8_MAX)
    {
        return false;
    }

    uint32_t total_len = 4U + 4U * ssrc_count;
    if (reason_len > 0)
    {
        total_len += 1U + (uint32_t) reason_len;
    }
    total_len = (total_len + 3U) & ~UINT32_C(3);

    if (total_len / 4U == 0 || total_len / 4U > (uint32_t) UINT16_MAX + 1U)
    {
        return false;
    }

    if (! junkdatagramsenderRtcpPutHeader(&writer,
                                          false,
                                          ssrc_count,
                                          kRtcpPtBye,
                                          (uint16_t) (total_len / 4U - 1U)))
    {
        return false;
    }

    for (uint8_t i = 0; i < ssrc_count; ++i)
    {
        if (! junkdatagramsenderRtpPutU32(&writer, ssrc_list[i]))
        {
            return false;
        }
    }

    if (reason_len > 0)
    {
        if (! junkdatagramsenderRtpPutU8(&writer, (uint8_t) reason_len) ||
            ! junkdatagramsenderRtpPutBytes(&writer, reason, (uint32_t) reason_len))
        {
            return false;
        }
    }

    while (writer.pos < total_len)
    {
        if (! junkdatagramsenderRtpPutU8(&writer, 0))
        {
            return false;
        }
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderSrtpBuildPacket(sbuf_t *buf, uint32_t write_limit, bool marker,
                                              uint8_t payload_type, uint16_t sequence_number,
                                              uint32_t timestamp, uint32_t ssrc, const uint32_t *csrc_list,
                                              uint8_t csrc_count, const uint8_t *extension_data,
                                              uint32_t extension_data_len, uint16_t extension_profile,
                                              const uint8_t *encrypted_payload,
                                              uint32_t encrypted_payload_len, const uint8_t *mki,
                                              uint32_t mki_len, const uint8_t *auth_tag,
                                              uint32_t auth_tag_len)
{
    junkdatagramsender_rtp_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = write_limit,
    };
    bool has_extension = extension_data_len > 0;

    if (payload_type > kRtpPayloadTypeMax || csrc_count > kRtpMaxCsrcCount ||
        (csrc_count > 0 && csrc_list == NULL) ||
        (encrypted_payload_len > 0 && encrypted_payload == NULL) || (mki_len > 0 && mki == NULL) ||
        (auth_tag_len > 0 && auth_tag == NULL) || (has_extension && extension_data == NULL) ||
        (extension_data_len % 4U) != 0)
    {
        return false;
    }

    if (! junkdatagramsenderRtpPutU8(&writer,
                                     (uint8_t) ((kRtpVersion << 6U) | (has_extension ? 0x10U : 0U) |
                                                (csrc_count & 0x0FU))) ||
        ! junkdatagramsenderRtpPutU8(&writer, (uint8_t) ((marker ? 0x80U : 0U) | payload_type)) ||
        ! junkdatagramsenderRtpPutU16(&writer, sequence_number) ||
        ! junkdatagramsenderRtpPutU32(&writer, timestamp) ||
        ! junkdatagramsenderRtpPutU32(&writer, ssrc))
    {
        return false;
    }

    for (uint8_t i = 0; i < csrc_count; ++i)
    {
        if (! junkdatagramsenderRtpPutU32(&writer, csrc_list[i]))
        {
            return false;
        }
    }

    if (has_extension)
    {
        if (extension_data_len / 4U > UINT16_MAX ||
            ! junkdatagramsenderRtpPutU16(&writer, extension_profile) ||
            ! junkdatagramsenderRtpPutU16(&writer, (uint16_t) (extension_data_len / 4U)) ||
            ! junkdatagramsenderRtpPutBytes(&writer, extension_data, extension_data_len))
        {
            return false;
        }
    }

    if (! junkdatagramsenderRtpPutBytes(&writer, encrypted_payload, encrypted_payload_len) ||
        ! junkdatagramsenderRtpPutBytes(&writer, mki, mki_len) ||
        ! junkdatagramsenderRtpPutBytes(&writer, auth_tag, auth_tag_len))
    {
        return false;
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderRtpGenerateRtp(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint8_t  payload[256];
    uint8_t  extension_data[16];
    uint32_t csrc_list[2];
    uint32_t extension_data_len = 0;
    uint16_t extension_profile  = 0;
    uint32_t write_limit        = junkdatagramsenderRtpWriteLimit(buf, args);
    uint8_t  csrc_count         = junkdatagramsenderRtpRandomCsrcList(csrc_list);
    bool     has_extension =
        junkdatagramsenderRtpRandomExtension(extension_data, &extension_data_len, &extension_profile);
    bool     padding       = (fastRand32() % 100U) < 10U;
    uint8_t  padding_count = padding ? (uint8_t) (4U * junkdatagramsenderRtpRandomRange(1, 3)) : 0;
    uint32_t overhead      = kRtpHeaderLen + 4U * csrc_count +
                        (has_extension ? 4U + extension_data_len : 0U) + padding_count;

    if (write_limit <= overhead || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    uint32_t payload_len = junkdatagramsenderRtpRandomPayloadLen(write_limit - overhead);
    if (payload_len > sizeof(payload))
    {
        payload_len = sizeof(payload);
    }
    getRandomBytes(payload, payload_len);

    sbufSetLength(buf, 0);
    return junkdatagramsenderRtpBuildPacket(buf,
                                            write_limit,
                                            padding,
                                            (fastRand32() % 100U) < 15U,
                                            junkdatagramsenderRtpRandomPayloadType(),
                                            (uint16_t) fastRand32(),
                                            fastRand32(),
                                            fastRand32(),
                                            csrc_count > 0 ? csrc_list : NULL,
                                            csrc_count,
                                            has_extension ? extension_data : NULL,
                                            has_extension ? extension_data_len : 0,
                                            extension_profile,
                                            payload,
                                            payload_len,
                                            padding_count);
}

static bool junkdatagramsenderRtpGenerateSrtp(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint8_t  encrypted_payload[256];
    uint8_t  extension_data[16];
    uint8_t  mki[kSrtpMaxMkiLen];
    uint8_t  auth_tag[kSrtpAuthTagGcmLen];
    uint32_t csrc_list[2];
    uint32_t extension_data_len = 0;
    uint16_t extension_profile  = 0;
    uint32_t write_limit        = junkdatagramsenderRtpWriteLimit(buf, args);
    uint8_t  csrc_count         = junkdatagramsenderRtpRandomCsrcList(csrc_list);
    bool     has_extension =
        junkdatagramsenderRtpRandomExtension(extension_data, &extension_data_len, &extension_profile);
    uint32_t mki_len = (fastRand32() % 100U) < 12U ? kSrtpMaxMkiLen : 0;

    uint32_t auth_roll = fastRand32() % 100U;
    uint32_t auth_tag_len =
        auth_roll < 70U ? kSrtpAuthTagDefaultLen : (auth_roll < 90U ? kSrtpAuthTagGcmLen : kSrtpAuthTagShortLen);

    uint32_t overhead = kRtpHeaderLen + 4U * csrc_count + (has_extension ? 4U + extension_data_len : 0U) +
                        mki_len + auth_tag_len;
    if (write_limit <= overhead || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    uint32_t encrypted_payload_len = junkdatagramsenderRtpRandomPayloadLen(write_limit - overhead);
    if (encrypted_payload_len > sizeof(encrypted_payload))
    {
        encrypted_payload_len = sizeof(encrypted_payload);
    }

    getRandomBytes(encrypted_payload, encrypted_payload_len);
    if (mki_len > 0)
    {
        getRandomBytes(mki, mki_len);
    }
    getRandomBytes(auth_tag, auth_tag_len);

    sbufSetLength(buf, 0);
    return junkdatagramsenderSrtpBuildPacket(buf,
                                             write_limit,
                                             (fastRand32() % 100U) < 15U,
                                             junkdatagramsenderRtpRandomPayloadType(),
                                             (uint16_t) fastRand32(),
                                             fastRand32(),
                                             fastRand32(),
                                             csrc_count > 0 ? csrc_list : NULL,
                                             csrc_count,
                                             has_extension ? extension_data : NULL,
                                             has_extension ? extension_data_len : 0,
                                             extension_profile,
                                             encrypted_payload,
                                             encrypted_payload_len,
                                             mki_len > 0 ? mki : NULL,
                                             mki_len,
                                             auth_tag,
                                             auth_tag_len);
}

static bool junkdatagramsenderRtpGenerateRtcpReceiverReport(sbuf_t *buf,
                                                            const junkdatagramsender_module_args_t *args)
{
    junkdatagramsender_rtcp_report_block_t report_blocks[2];
    uint32_t write_limit = junkdatagramsenderRtpWriteLimit(buf, args);
    uint8_t  report_count = junkdatagramsenderRtcpRandomReportBlockCount(write_limit, 8);

    if (write_limit < 8 || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    for (uint8_t i = 0; i < report_count; ++i)
    {
        junkdatagramsenderRtcpRandomReportBlock(&report_blocks[i]);
    }

    sbufSetLength(buf, 0);
    return junkdatagramsenderRtcpBuildReceiverReport(buf,
                                                     write_limit,
                                                     fastRand32(),
                                                     report_count > 0 ? report_blocks : NULL,
                                                     report_count);
}

static bool junkdatagramsenderRtpGenerateRtcpSenderReport(sbuf_t *buf,
                                                          const junkdatagramsender_module_args_t *args)
{
    junkdatagramsender_rtcp_report_block_t report_blocks[2];
    struct timeval tv;
    uint32_t write_limit = junkdatagramsenderRtpWriteLimit(buf, args);
    uint8_t  report_count = junkdatagramsenderRtcpRandomReportBlockCount(write_limit, 28);

    if (write_limit < 28 || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    for (uint8_t i = 0; i < report_count; ++i)
    {
        junkdatagramsenderRtcpRandomReportBlock(&report_blocks[i]);
    }

    getTimeOfDay(&tv, NULL);
    uint32_t ntp_msw = (uint32_t) ((uint64_t) tv.tv_sec + 2208988800ULL);
    uint32_t ntp_lsw = (uint32_t) ((((uint64_t) (uint32_t) tv.tv_usec) * UINT64_C(4294967296)) / 1000000ULL);

    sbufSetLength(buf, 0);
    return junkdatagramsenderRtcpBuildSenderReport(buf,
                                                   write_limit,
                                                   fastRand32(),
                                                   ntp_msw,
                                                   ntp_lsw,
                                                   fastRand32(),
                                                   junkdatagramsenderRtpRandomRange(1, 200000),
                                                   junkdatagramsenderRtpRandomRange(1200, 4000000),
                                                   report_count > 0 ? report_blocks : NULL,
                                                   report_count);
}

static const char *junkdatagramsenderRtpRandomCname(char *buf, size_t buf_len)
{
    static const char *hosts[] = {
        "host.local",
        "media.local",
        "call.local",
        "ww.local",
    };

    if (junkdatagramsenderRtpFormatFits(
            stringNPrintf(buf,
                          buf_len,
                          "u%04x@%s",
                          (unsigned int) (fastRand32() & 0xFFFFU),
                          hosts[fastRand32() % (sizeof(hosts) / sizeof(hosts[0]))]),
            buf_len))
    {
        return buf;
    }
    return "user@host.local";
}

static bool junkdatagramsenderRtpGenerateRtcpSdes(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    char     cname[48];
    uint32_t write_limit = junkdatagramsenderRtpWriteLimit(buf, args);

    if (write_limit < 16 || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    sbufSetLength(buf, 0);
    return junkdatagramsenderRtcpBuildSdesCname(
        buf, write_limit, fastRand32(), junkdatagramsenderRtpRandomCname(cname, sizeof(cname)));
}

static const char *junkdatagramsenderRtpRandomByeReason(void)
{
    static const char *reasons[] = {
        "leaving",
        "timeout",
        "session ended",
        "normal",
    };

    if ((fastRand32() % 100U) < 55U)
    {
        return NULL;
    }
    return reasons[fastRand32() % (sizeof(reasons) / sizeof(reasons[0]))];
}

static bool junkdatagramsenderRtpGenerateRtcpBye(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t ssrc_list[2];
    uint32_t write_limit = junkdatagramsenderRtpWriteLimit(buf, args);
    uint8_t  ssrc_count  = (write_limit >= 16 && (fastRand32() % 100U) < 18U) ? 2 : 1;

    if (write_limit < 8 || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    for (uint8_t i = 0; i < ssrc_count; ++i)
    {
        ssrc_list[i] = fastRand32();
    }

    sbufSetLength(buf, 0);
    return junkdatagramsenderRtcpBuildBye(
        buf, write_limit, ssrc_list, ssrc_count, junkdatagramsenderRtpRandomByeReason());
}

bool junkdatagramsenderRtpRtcpSrtpGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    typedef bool (*generator_fn)(sbuf_t *buf, const junkdatagramsender_module_args_t *args);

    static const generator_fn generators[] = {
        junkdatagramsenderRtpGenerateRtp,
        junkdatagramsenderRtpGenerateRtp,
        junkdatagramsenderRtpGenerateSrtp,
        junkdatagramsenderRtpGenerateRtcpSenderReport,
        junkdatagramsenderRtpGenerateRtcpReceiverReport,
        junkdatagramsenderRtpGenerateRtcpSdes,
        junkdatagramsenderRtpGenerateRtcpBye,
    };

    uint32_t first = fastRand32() % (sizeof(generators) / sizeof(generators[0]));
    for (uint32_t i = 0; i < (uint32_t) (sizeof(generators) / sizeof(generators[0])); ++i)
    {
        generator_fn generate = generators[(first + i) % (sizeof(generators) / sizeof(generators[0]))];
        if (generate(buf, args) && sbufGetLength(buf) > 0)
        {
            return true;
        }
        sbufSetLength(buf, 0);
    }

    return false;
}
