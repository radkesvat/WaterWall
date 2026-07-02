#include "structure.h"

#include "loggers/network_logger.h"

static uint8_t bgp4clientRandomNonOpenType(void)
{
    return (uint8_t) (kBgp4ClientTypeUpdate +
                      (fastRand() % (kBgp4ClientTypeRouteRefresh - kBgp4ClientTypeUpdate + 1)));
}

bool bgp4clientLoadSettings(bgp4client_tstate_t *ts, const cJSON *settings)
{
    char *password = NULL;
    getStringFromJsonObjectOrDefault(&password, settings, "password", "passwd");
    ts->password_hash = calcHashBytes(password, stringLength(password));
    memoryFree(password);

    ts->as_number = (uint16_t) fastRand();
    ts->router_id = fastRand() * 3U;
    return true;
}

void bgp4clientCloseLine(tunnel_t *t, line_t *l)
{
    bgp4client_lstate_t *ls = lineGetState(l, t);
    bgp4clientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}

bool bgp4clientWrapPayload(tunnel_t *t, line_t *l, sbuf_t **buf_io, uint8_t type)
{
    discard t;

    sbuf_t  *buf      = *buf_io;
    uint32_t body_len = sbufGetLength(buf) + kBgp4ClientTypeSize;

    if (body_len > kBgp4ClientMaxBodyLength)
    {
        LOGW("Bgp4Client: payload too large to wrap as a BGP message");
        lineReuseBuffer(l, buf);
        return false;
    }

    sbufShiftLeft(buf, kBgp4ClientTypeSize);
    sbufWriteUI8(buf, type);

    uint16_t body_len_network = htons((uint16_t) sbufGetLength(buf));
    sbufShiftLeft(buf, kBgp4ClientLengthSize);
    sbufWriteUnAlignedUI16(buf, body_len_network);

    sbufShiftLeft(buf, kBgp4ClientMarkerLength);
    memorySet(sbufGetMutablePtr(buf), kBgp4ClientMarkerByte, kBgp4ClientMarkerLength);

    *buf_io = buf;
    return true;
}

bool bgp4clientWrapFirstOpenPayload(tunnel_t *t, line_t *l, sbuf_t **buf_io)
{
    bgp4client_tstate_t *ts  = tunnelGetState(t);
    sbuf_t              *buf = *buf_io;
    uint8_t              optional_len =
        (uint8_t) (kBgp4ClientOpenOptionalMin + (fastRand() % kBgp4ClientOpenOptionalRange));

    sbufShiftLeft(buf, kBgp4ClientOpenHeaderSize + optional_len);

    uint8_t *open = sbufGetMutablePtr(buf);
    memoryZero(open, kBgp4ClientOpenHeaderSize + optional_len);

    uint16_t as_number_network = htons(ts->as_number);
    uint16_t hold_time_network = htons(90);
    uint32_t router_id_network = htonl(ts->router_id);

    open[0] = 4;
    sbufByteCopy(open + 1, &as_number_network, sizeof(as_number_network));
    sbufByteCopy(open + 3, &hold_time_network, sizeof(hold_time_network));
    sbufByteCopy(open + 5, &router_id_network, sizeof(router_id_network));
    open[9] = optional_len;

    for (uint8_t i = 0; i < optional_len; ++i)
    {
        open[kBgp4ClientOpenHeaderSize + i] = (uint8_t) (fastRand() % 200);
    }

    return bgp4clientWrapPayload(t, l, buf_io, kBgp4ClientTypeOpen);
}

bool bgp4clientReadFrame(tunnel_t *t, line_t *l, buffer_stream_t *stream, sbuf_t **payload_out)
{
    discard t;
    *payload_out = NULL;

    if (bufferstreamGetBufLen(stream) < kBgp4ClientFrameHeaderSize + kBgp4ClientTypeSize)
    {
        return true;
    }

    uint8_t marker[kBgp4ClientMarkerLength];
    bufferstreamViewBytesAt(stream, 0, marker, sizeof(marker));

    for (uint32_t i = 0; i < kBgp4ClientMarkerLength; ++i)
    {
        if (marker[i] != kBgp4ClientMarkerByte)
        {
            LOGE("Bgp4Client: invalid BGP marker");
            return false;
        }
    }

    uint16_t body_len_network = 0;
    bufferstreamViewBytesAt(stream, kBgp4ClientMarkerLength, (uint8_t *) &body_len_network,
                            sizeof(body_len_network));
    uint16_t body_len = ntohs(body_len_network);

    if (body_len <= kBgp4ClientTypeSize)
    {
        LOGE("Bgp4Client: BGP message is too short");
        return false;
    }

    size_t frame_len = kBgp4ClientFrameHeaderSize + (size_t) body_len;
    if (bufferstreamGetBufLen(stream) < frame_len)
    {
        if (bufferstreamGetBufLen(stream) > kBgp4ClientMaxBufferedBytes)
        {
            LOGE("Bgp4Client: BGP read buffer overflow");
            return false;
        }
        return true;
    }

    sbuf_t *frame = bufferstreamReadExact(stream, frame_len);
    sbufShiftRight(frame, kBgp4ClientFrameHeaderSize + kBgp4ClientTypeSize);

    if (sbufGetLength(frame) == 0)
    {
        LOGE("Bgp4Client: BGP message had no payload");
        lineReuseBuffer(l, frame);
        return false;
    }

    *payload_out = frame;
    return true;
}

uint8_t bgp4clientNextPayloadType(void)
{
    return bgp4clientRandomNonOpenType();
}
