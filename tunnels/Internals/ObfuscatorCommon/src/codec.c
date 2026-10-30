#include "ObfuscatorCommon/codec.h"

static uint32_t obfuscatorGetSkipLength(sbuf_t *buf, uint32_t skip)
{
    if (skip == kObfuscatorSkipNone)
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

    if (ip_header_length < IP_HLEN || packet_length < ip_header_length)
    {
        return 0;
    }

    if (skip == kObfuscatorSkipIpv4)
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

void obfuscatorApplyXor(sbuf_t *buf, uint32_t skip, uint8_t key)
{
    assert(! sbufIsSplice(buf));
    const uint32_t length      = sbufGetLength(buf);
    const uint32_t skip_length = obfuscatorGetSkipLength(buf, skip);
    if (skip_length < length)
        obfuscatorXorByte(sbufGetMutablePtr(buf) + skip_length, length - skip_length, key);
}

static void writeHeader(sbuf_t *buf, uint32_t length)
{
    uint8_t *header = sbufGetMutablePtr(buf);
    header[0]       = 23;
    header[1]       = 3;
    header[2]       = 3;
    header[3]       = (uint8_t) (length >> 8);
    header[4]       = (uint8_t) length;
}

sbuf_t *obfuscatorWrapRecord(buffer_pool_t *pool, sbuf_t *buf)
{
    assert(! sbufIsSplice(buf));
    const uint32_t length = sbufGetLength(buf);
    if (length > UINT16_MAX)
    {
        bufferpoolReuseBuffer(pool, buf);
        return NULL;
    }
    buf = sbufEnsureLeftCapacity(pool, buf, kObfuscatorTlsRecordHeaderSize);
    sbufShiftLeft(buf, kObfuscatorTlsRecordHeaderSize);
    writeHeader(buf, length);
    return buf;
}

bool obfuscatorStripRecord(sbuf_t *buf)
{
    assert(! sbufIsSplice(buf));
    if (sbufGetLength(buf) < kObfuscatorTlsRecordHeaderSize)
        return false;
    const uint8_t *header = sbufGetRawPtr(buf);
    const uint32_t length = ((uint32_t) header[3] << 8) | header[4];
    if (header[0] != 23 || header[1] != 3 || header[2] != 3 ||
        length != sbufGetLength(buf) - kObfuscatorTlsRecordHeaderSize)
        return false;
    sbufShiftRight(buf, kObfuscatorTlsRecordHeaderSize);
    return true;
}

sbuf_t *obfuscatorEncodeStream(buffer_pool_t *pool, sbuf_t *buf, uint32_t skip, uint8_t key)
{
    assert(! sbufIsSplice(buf));
    const uint32_t length = sbufGetLength(buf);
    if (length <= UINT16_MAX && sbufGetLeftCapacity(buf) >= kObfuscatorTlsRecordHeaderSize)
    {
        obfuscatorApplyXor(buf, skip, key);
        sbufShiftLeft(buf, kObfuscatorTlsRecordHeaderSize);
        writeHeader(buf, length);
        return buf;
    }
    const uint64_t records = max(UINT64_C(1), ((uint64_t) length + 65534) / 65535);
    const uint64_t total   = length + kObfuscatorTlsRecordHeaderSize * records;
    sbuf_t        *out     = bufferpoolTryGetBestFit(pool, total, bufferpoolGetLargeBufferPadding(pool));
    if (! out)
    {
        bufferpoolReuseBuffer(pool, buf);
        return NULL;
    }
    const uint32_t start = out->curpos;
    for (uint64_t record = 0; record < records; ++record)
    {
        const uint32_t n = min(sbufGetLength(buf), UINT16_MAX);
        writeHeader(out, n);
        out->curpos += kObfuscatorTlsRecordHeaderSize;
        sbufSetLength(out, 0);
        sbufMoveTo(out, buf, n);
        obfuscatorApplyXor(out, skip, key);
        out->curpos += n;
    }
    out->curpos = start;
    sbufSetLength(out, (uint32_t) total);
    bufferpoolReuseBuffer(pool, buf);
    return out;
}

obfuscator_decode_result_t obfuscatorDecodeStream(buffer_pool_t *pool, buffer_stream_t *stream, sbuf_t *buf,
                                                  uint32_t skip, uint8_t key, sbuf_t **out)
{
    assert(! sbufIsSplice(buf));
    *out                 = NULL;
    const uint64_t total = (uint64_t) bufferstreamGetBufLen(stream) + sbufGetLength(buf);
    if (total > kObfuscatorMaxBufferedStreamBytes)
    {
        bufferpoolReuseBuffer(pool, buf);
        return kObfuscatorDecodeOverflow;
    }
    if (sbufGetLength(buf) == 0)
    {
        bufferpoolReuseBuffer(pool, buf);
        return kObfuscatorDecodeIncomplete;
    }
    bufferstreamPush(stream, buf);
    while (bufferstreamGetBufLen(stream) >= kObfuscatorTlsRecordHeaderSize)
    {
        uint8_t header[kObfuscatorTlsRecordHeaderSize];
        bufferstreamViewBytesAt(stream, 0, header, sizeof(header));
        if (header[0] != 23 || header[1] != 3 || header[2] != 3)
        {
            if (*out)
            {
                bufferpoolReuseBuffer(pool, *out);
                *out = NULL;
            }
            return kObfuscatorDecodeInvalid;
        }
        const uint32_t length = ((uint32_t) header[3] << 8) | header[4];
        if (bufferstreamGetBufLen(stream) < length + kObfuscatorTlsRecordHeaderSize)
            break;
        if (*out == NULL)
        {
            const size_t buffered = bufferstreamGetBufLen(stream);
            assert(buffered <= kObfuscatorMaxBufferedStreamBytes);
            *out = bufferpoolGetBestFit(pool, (uint32_t) buffered, bufferpoolGetLargeBufferPadding(pool));
        }
        sbuf_t *record = bufferstreamReadExact(stream, length + kObfuscatorTlsRecordHeaderSize);
        sbufShiftRight(record, kObfuscatorTlsRecordHeaderSize);
        obfuscatorApplyXor(record, skip, key);
        sbufMoveTo(*out, record, length);
        bufferpoolReuseBuffer(pool, record);
    }
    return *out ? kObfuscatorDecodeReady : kObfuscatorDecodeIncomplete;
}
