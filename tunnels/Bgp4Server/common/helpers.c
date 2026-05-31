#include "structure.h"

#include "loggers/network_logger.h"

static uint8_t bgp4serverRandomNonOpenType(void)
{
    return (uint8_t) (kBgp4ServerTypeUpdate +
                      (fastRand() % (kBgp4ServerTypeRouteRefresh - kBgp4ServerTypeUpdate + 1)));
}

bool bgp4serverLoadSettings(bgp4server_tstate_t *ts, const cJSON *settings)
{
    char *password = NULL;
    getStringFromJsonObjectOrDefault(&password, settings, "password", "passwd");
    ts->password_hash = calcHashBytes(password, stringLength(password));
    memoryFree(password);

    ts->as_number = (uint16_t) fastRand();
    ts->router_id = fastRand() * 3U;
    return true;
}

void bgp4serverCloseLine(tunnel_t *t, line_t *l)
{
    lineLock(l);

    bgp4server_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kBgp4ServerPhaseNone)
    {
        lineUnlock(l);
        return;
    }

    bgp4serverLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);

    lineUnlock(l);
}

bool bgp4serverWrapPayload(tunnel_t *t, line_t *l, sbuf_t **buf_io, uint8_t type)
{
    discard t;

    sbuf_t  *buf      = *buf_io;
    uint32_t body_len = sbufGetLength(buf) + kBgp4ServerTypeSize;

    if (body_len > kBgp4ServerMaxBodyLength)
    {
        LOGW("Bgp4Server: payload too large to wrap as a BGP message");
        lineReuseBuffer(l, buf);
        return false;
    }

    sbufShiftLeft(buf, kBgp4ServerTypeSize);
    sbufWriteUI8(buf, type);

    uint16_t body_len_network = htons((uint16_t) sbufGetLength(buf));
    sbufShiftLeft(buf, kBgp4ServerLengthSize);
    sbufWriteUnAlignedUI16(buf, body_len_network);

    sbufShiftLeft(buf, kBgp4ServerMarkerLength);
    memorySet(sbufGetMutablePtr(buf), kBgp4ServerMarkerByte, kBgp4ServerMarkerLength);

    *buf_io = buf;
    return true;
}

bool bgp4serverReadFrame(tunnel_t *t, line_t *l, buffer_stream_t *stream, sbuf_t **body_out)
{
    discard t;
    discard l;
    *body_out = NULL;

    if (bufferstreamGetBufLen(stream) < kBgp4ServerFrameHeaderSize + kBgp4ServerTypeSize)
    {
        return true;
    }

    uint8_t marker[kBgp4ServerMarkerLength];
    bufferstreamViewBytesAt(stream, 0, marker, sizeof(marker));

    for (uint32_t i = 0; i < kBgp4ServerMarkerLength; ++i)
    {
        if (marker[i] != kBgp4ServerMarkerByte)
        {
            LOGE("Bgp4Server: invalid BGP marker");
            return false;
        }
    }

    uint16_t body_len_network = 0;
    bufferstreamViewBytesAt(stream, kBgp4ServerMarkerLength, (uint8_t *) &body_len_network,
                            sizeof(body_len_network));
    uint16_t body_len = ntohs(body_len_network);

    if (body_len <= kBgp4ServerTypeSize)
    {
        LOGE("Bgp4Server: BGP message is too short");
        return false;
    }

    size_t frame_len = kBgp4ServerFrameHeaderSize + (size_t) body_len;
    if (bufferstreamGetBufLen(stream) < frame_len)
    {
        if (bufferstreamGetBufLen(stream) > kBgp4ServerMaxBufferedBytes)
        {
            LOGE("Bgp4Server: BGP read buffer overflow");
            return false;
        }
        return true;
    }

    sbuf_t *frame = bufferstreamReadExact(stream, frame_len);
    sbufShiftRight(frame, kBgp4ServerFrameHeaderSize);

    *body_out = frame;
    return true;
}

bool bgp4serverStripUpstreamBody(tunnel_t *t, line_t *l, bgp4server_lstate_t *ls, sbuf_t *body)
{
    discard t;

    if (! ls->open_received)
    {
        if (sbufGetLength(body) < kBgp4ServerTypeSize + kBgp4ServerOpenHeaderSize)
        {
            LOGE("Bgp4Server: first BGP message is shorter than an OPEN header");
            lineReuseBuffer(l, body);
            return false;
        }

        uint8_t *raw = sbufGetMutablePtr(body);
        if (raw[0] != kBgp4ServerTypeOpen)
        {
            LOGE("Bgp4Server: first BGP message type was not OPEN");
            lineReuseBuffer(l, body);
            return false;
        }

        uint8_t optional_len = raw[kBgp4ServerTypeSize + kBgp4ServerOpenHeaderSize - 1];
        uint32_t prefix_len  = kBgp4ServerTypeSize + kBgp4ServerOpenHeaderSize + optional_len;

        if (sbufGetLength(body) <= prefix_len)
        {
            LOGE("Bgp4Server: OPEN message has no tunneled payload");
            lineReuseBuffer(l, body);
            return false;
        }

        ls->open_received = true;
        sbufShiftRight(body, prefix_len);
        return true;
    }

    sbufShiftRight(body, kBgp4ServerTypeSize);
    if (sbufGetLength(body) == 0)
    {
        LOGE("Bgp4Server: BGP message had no payload");
        lineReuseBuffer(l, body);
        return false;
    }

    return true;
}

uint8_t bgp4serverNextPayloadType(void)
{
    return bgp4serverRandomNonOpenType();
}
