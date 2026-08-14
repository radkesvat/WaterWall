#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kObfuscatorTlsApplicationDataType = 23,
    kObfuscatorTlsLegacyVersionMajor  = 0x03,
    kObfuscatorTlsLegacyVersionMinor  = 0x03
};

static uint32_t obfuscatorclientGetSkipLength(tunnel_t *t, sbuf_t *buf)
{
    obfuscatorclient_tstate_t *ts = tunnelGetState(t);

    if (ts->skip == kObfuscatorSkipNone)
    {
        return 0;
    }

    uint32_t packet_length = sbufGetLength(buf);

    if (packet_length < sizeof(struct ip_hdr))
    {
        return 0;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetRawPtr(buf);

    if (IPH_V(ipheader) != 4)
    {
        return 0;
    }

    uint32_t ip_header_length = ((uint32_t) IPH_HL(ipheader)) * 4U;

    if (ip_header_length < IP_HLEN || ip_header_length > IP_HLEN_MAX || packet_length < ip_header_length)
    {
        return 0;
    }

    if (ts->skip == kObfuscatorSkipIpv4)
    {
        return ip_header_length;
    }

    if (IPH_PROTO(ipheader) == IPPROTO_TCP)
    {
        if (packet_length < ip_header_length + sizeof(struct tcp_hdr))
        {
            return ip_header_length;
        }

        struct tcp_hdr *tcp_header        = (struct tcp_hdr *) (((uint8_t *) sbufGetRawPtr(buf)) + ip_header_length);
        uint32_t        tcp_header_length = TCPH_HDRLEN_BYTES(tcp_header);

        if (tcp_header_length < sizeof(struct tcp_hdr) || packet_length < ip_header_length + tcp_header_length)
        {
            return ip_header_length;
        }

        return ip_header_length + tcp_header_length;
    }

    if (IPH_PROTO(ipheader) == IPPROTO_UDP)
    {
        if (packet_length < ip_header_length + UDP_HLEN)
        {
            return ip_header_length;
        }

        return ip_header_length + UDP_HLEN;
    }

    return ip_header_length;
}

void obfuscatorclientApplyXor(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard l;

    obfuscatorclient_tstate_t *ts          = tunnelGetState(t);
    uint32_t                   payload_len = sbufGetLength(buf);
    uint32_t                   skip_length = obfuscatorclientGetSkipLength(t, buf);

    if (skip_length >= payload_len)
    {
        return;
    }

    obfuscatorclientXorByte(sbufGetMutablePtr(buf) + skip_length, payload_len - skip_length, ts->xor_key);
}

static sbuf_t *obfuscatorclientCloneBufferWithPadding(line_t *l, sbuf_t *buf)
{
    buffer_pool_t *pool        = lineGetBufferPool(l);
    uint32_t       payload_len = sbufGetLength(buf);
    sbuf_t        *clone       = NULL;

    if (payload_len <= bufferpoolGetSmallBufferSize(pool))
    {
        clone = bufferpoolGetSmallBuffer(pool);
    }
    else if (payload_len <= bufferpoolGetLargeBufferSize(pool))
    {
        clone = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        clone = sbufCreateWithPadding(payload_len, kObfuscatorTlsRecordHeaderSize);
    }

    sbufSetLength(clone, payload_len);
    sbufWriteBuf(clone, buf, payload_len);
    sbufTransferLifetime(buf, clone);
    lineReuseBuffer(l, buf);

    return clone;
}

bool obfuscatorclientWrapTlsRecordHeader(line_t *l, sbuf_t **buf_io)
{
    sbuf_t  *buf         = *buf_io;
    uint32_t payload_len = sbufGetLength(buf);

    if (payload_len > UINT16_MAX)
    {
        LOGW("ObfuscatorClient: payload length %u exceeds TLS record header limit, dropped", payload_len);
        lineReuseBuffer(l, buf);
        return false;
    }

    if (sbufGetLeftCapacity(buf) < kObfuscatorTlsRecordHeaderSize)
    {
        buf = obfuscatorclientCloneBufferWithPadding(l, buf);
    }

    assert(sbufGetLeftCapacity(buf) >= kObfuscatorTlsRecordHeaderSize);

    sbufShiftLeft(buf, kObfuscatorTlsRecordHeaderSize);

    uint8_t *record = sbufGetMutablePtr(buf);
    record[0]       = kObfuscatorTlsApplicationDataType;
    record[1]       = kObfuscatorTlsLegacyVersionMajor;
    record[2]       = kObfuscatorTlsLegacyVersionMinor;

    uint16_t payload_len_network = htons((uint16_t) payload_len);
    sbufByteCopy(record + 3, &payload_len_network, sizeof(payload_len_network));

    *buf_io = buf;
    return true;
}

bool obfuscatorclientStripTlsRecordHeader(line_t *l, sbuf_t *buf)
{
    if (sbufGetLength(buf) < kObfuscatorTlsRecordHeaderSize)
    {
        LOGW("ObfuscatorClient: truncated TLS-like payload (%u bytes), dropped", sbufGetLength(buf));
        lineReuseBuffer(l, buf);
        return false;
    }

    uint8_t *record = sbufGetMutablePtr(buf);

    if (record[0] != kObfuscatorTlsApplicationDataType || record[1] != kObfuscatorTlsLegacyVersionMajor ||
        record[2] != kObfuscatorTlsLegacyVersionMinor)
    {
        LOGW("ObfuscatorClient: invalid TLS-like record header, dropped");
        lineReuseBuffer(l, buf);
        return false;
    }

    uint16_t payload_len_network = 0;
    sbufByteCopy(&payload_len_network, record + 3, sizeof(payload_len_network));

    uint32_t payload_len          = ntohs(payload_len_network);
    uint32_t expected_payload_len = sbufGetLength(buf) - kObfuscatorTlsRecordHeaderSize;

    if (payload_len != expected_payload_len)
    {
        LOGW(
            "ObfuscatorClient: TLS-like record length mismatch (%u != %u), dropped", payload_len, expected_payload_len);
        lineReuseBuffer(l, buf);
        return false;
    }

    sbufShiftRight(buf, kObfuscatorTlsRecordHeaderSize);
    return true;
}
