#include "structure.h"

uint32_t streamfragmenterTlsNeed(const streamfragmenter_tls_parser_t *parser)
{
    assert(parser != NULL);
    if (parser->record_header_used < 5)
        return 5 - parser->record_header_used;
    if (parser->handshake_header_used < 4)
        return min((uint32_t) parser->record_remaining, 4U - parser->handshake_header_used);
    return min((uint32_t) parser->record_remaining, parser->handshake_total - parser->handshake_seen);
}

streamfragmenter_tls_result_t streamfragmenterTlsFeed(streamfragmenter_tls_parser_t *parser, const uint8_t *bytes,
                                                      uint32_t length)
{
    assert(parser != NULL && bytes != NULL && length > 0 && length <= streamfragmenterTlsNeed(parser));
    if (parser->record_header_used < 5)
    {
        for (uint32_t i = 0; i < length; ++i)
        {
            const uint8_t byte = bytes[i];
            switch (parser->record_header_used)
            {
            case 0:
                if (byte != 22)
                    return kStreamFragmenterTlsPassUnchanged;
                break;
            case 1:
                if (byte != 3)
                    return kStreamFragmenterTlsPassUnchanged;
                break;
            case 2:
                if (byte < 1 || byte > 3)
                    return kStreamFragmenterTlsPassUnchanged;
                break;
            default:
                break;
            }
            parser->record_header[parser->record_header_used++] = byte;
        }
        if (parser->record_header_used == 5)
        {
            const uint32_t payload = ((uint32_t) parser->record_header[3] << 8) | parser->record_header[4];
            if (payload == 0 || payload > 16384)
                return kStreamFragmenterTlsPassUnchanged;
            parser->record_remaining = (uint16_t) payload;
        }
        return kStreamFragmenterTlsIncomplete;
    }

    parser->record_remaining -= (uint16_t) length;
    if (parser->handshake_header_used < 4)
    {
        for (uint32_t i = 0; i < length; ++i)
        {
            if (parser->handshake_header_used == 0 && bytes[i] != 1)
                return kStreamFragmenterTlsPassUnchanged;
            parser->handshake_header[parser->handshake_header_used++] = bytes[i];
        }
        parser->handshake_seen += length;
        if (parser->record_remaining == 0)
            parser->record_header_used = 0;
        if (parser->handshake_header_used == 4)
        {
            const uint32_t body = ((uint32_t) parser->handshake_header[1] << 16) |
                                  ((uint32_t) parser->handshake_header[2] << 8) | parser->handshake_header[3];
            if (body < 41 || body > kStreamFragmenterMaxHello - 4)
                return kStreamFragmenterTlsPassUnchanged;
            parser->handshake_total = body + 4;
            return kStreamFragmenterTlsHeaderReady;
        }
        return kStreamFragmenterTlsIncomplete;
    }

    parser->handshake_seen += length;
    if (parser->handshake_seen == parser->handshake_total)
        return parser->record_remaining == 0 ? kStreamFragmenterTlsComplete : kStreamFragmenterTlsPassUnchanged;
    if (parser->record_remaining == 0)
        parser->record_header_used = 0;
    return kStreamFragmenterTlsIncomplete;
}

static uint32_t nextSelectedCut(uint64_t selected, const streamfragmenter_tstate_t *settings, uint8_t *index)
{
    while (*index < settings->cut_count && (selected & (UINT64_C(1) << *index)) == 0)
        ++*index;
    return *index < settings->cut_count ? settings->cuts[*index].offset : UINT32_MAX;
}

uint32_t streamfragmenterTlsRewriteLength(const sbuf_t *original, uint64_t selected_cuts,
                                          const streamfragmenter_tstate_t *settings)
{
    assert(original != NULL && ! sbufIsSplice(original) && settings != NULL && selected_cuts != 0);
    const uint8_t *wire     = sbufGetRawPtr(original);
    const uint32_t length   = sbufGetLength(original);
    uint32_t       position = 0, handshake = 0, extra = 0;
    uint8_t        index = 0;
    uint32_t       cut   = nextSelectedCut(selected_cuts, settings, &index);
    while (position < length)
    {
        assert(length - position >= 6);
        const uint32_t body = ((uint32_t) wire[position + 3] << 8) | wire[position + 4];
        assert(body > 0 && body <= 16384 && body <= length - position - 5);
        while (cut <= handshake + body)
        {
            if (cut > handshake && cut < handshake + body)
                ++extra;
            ++index;
            cut = nextSelectedCut(selected_cuts, settings, &index);
        }
        position += 5 + body;
        handshake += body;
    }
    assert(position == length && handshake <= kStreamFragmenterMaxHello && extra <= kStreamFragmenterMaxCuts);
    assert(length + extra * 5 <= kStreamFragmenterMaxRewrite);
    return length + extra * 5;
}

bool streamfragmenterTlsRewrite(const sbuf_t *original, uint64_t selected_cuts,
                                const streamfragmenter_tstate_t *settings, sbuf_t *output, uint32_t *mapped_cuts)
{
    assert(original != NULL && output != NULL && ! sbufIsSplice(original) && ! sbufIsSplice(output) &&
           settings != NULL && mapped_cuts != NULL && selected_cuts != 0);
    const uint8_t *wire          = sbufGetRawPtr(original);
    uint8_t       *dest          = sbufGetMutablePtr(output);
    const uint32_t length        = sbufGetLength(original);
    const uint32_t target_length = streamfragmenterTlsRewriteLength(original, selected_cuts, settings);
    if (target_length > sbufGetMaximumWriteableSize(output))
        return false;

    uint32_t position = 0, written = 0, handshake = 0;
    uint8_t  index = 0;
    uint32_t cut   = nextSelectedCut(selected_cuts, settings, &index);
    while (position < length)
    {
        const uint8_t *header  = wire + position;
        const uint32_t body    = ((uint32_t) header[3] << 8) | header[4];
        const uint8_t *payload = header + 5;
        const uint32_t end     = handshake + body;
        uint32_t       segment = handshake;
        while (segment < end)
        {
            const uint32_t segment_end = min(cut, end);
            assert(segment_end > segment);
            const uint32_t segment_length = segment_end - segment;
            dest[written++]               = header[0];
            dest[written++]               = header[1];
            dest[written++]               = header[2];
            dest[written++]               = (uint8_t) (segment_length >> 8);
            dest[written++]               = (uint8_t) segment_length;
            memoryCopy(dest + written, payload + segment - handshake, segment_length);
            written += segment_length;
            segment = segment_end;
            if (segment == cut)
            {
                mapped_cuts[index++] = written;
                cut                  = nextSelectedCut(selected_cuts, settings, &index);
            }
        }
        position += body + 5;
        handshake = end;
    }
    assert(written == target_length && position == length);
    sbufSetLength(output, written);
    return true;
}
