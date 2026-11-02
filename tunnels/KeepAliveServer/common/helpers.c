#include "structure.h"

#include "loggers/network_logger.h"

static bool keepaliveserverSendFrame(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t kind)
{
    const uint32_t length = sbufGetLength(buf);
    assert(length <= kKeepAliveServerMaxPayloadChunkSize);
    assert(sbufGetLeftCapacity(buf) >= kKeepAliveServerFramePrefixSize);
    /* Only the real left padding is written, including for a private-pipe body. */
    sbufShiftLeft(buf, kKeepAliveServerFramePrefixSize);
    uint8_t *header         = sbufGetMutablePtr(buf);
    uint32_t network_length = htonl(length + kKeepAliveServerFrameTypeSize);
    sbufByteCopy(header, &network_length, sizeof(network_length));
    header[kKeepAliveServerFrameLengthSize] = kind;
    return lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
}

static bool keepaliveserverSendControlFrame(tunnel_t *t, line_t *l, uint8_t kind)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);
    return keepaliveserverSendFrame(t, l, buf, kind);
}

void keepaliveserverSendNormalFrameDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    assert(spliceframereaderIsAttached(&ls->reader));
    const uint32_t length = sbufGetLength(buf);
    if (length == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->write_draining)
    {
        const size_t pending =
            bufferqueueGetBufLen(&ls->write_reentry) + (ls->write_active != NULL ? sbufGetLength(ls->write_active) : 0);
        const size_t active_charge = ls->write_active != NULL ? sbufGetQueueCharge(ls->write_active) : 0;
        const size_t queued_charge = bufferqueueGetCharge(&ls->write_reentry);
        if (pending > kKeepAliveServerMaxReentryBytes || length > kKeepAliveServerMaxReentryBytes - pending ||
            active_charge > kKeepAliveServerMaxReentryCharge ||
            queued_charge > kKeepAliveServerMaxReentryCharge - active_charge ||
            sbufGetQueueCharge(buf) > kKeepAliveServerMaxReentryCharge - active_charge - queued_charge ||
            ! bufferqueueTryPushBack(&ls->write_reentry, &buf))
        {
            lineReuseBuffer(l, buf);
            keepaliveserverCloseLineFromProtocolError(t, l);
            return;
        }
        return;
    }

    buffer_pool_t *pool = lineGetBufferPool(l);
    ls->write_draining  = true;
    ls->write_active    = buf;
    lineRef(l);
    while (ls->write_active != NULL)
    {
        sbuf_t        *source = ls->write_active;
        const uint32_t bytes  = min(sbufGetLength(source), (uint32_t) kKeepAliveServerMaxPayloadChunkSize);
        sbuf_t        *frame;
        if (bytes == sbufGetLength(source))
        {
            frame            = source;
            ls->write_active = NULL;
        }
        else
        {
            sbuf_t *destination = sbufIsSplice(source) ? bufferpoolGetSpliceBuffer(pool) : NULL;
            frame = sbufMoveRangeTo(pool, source, destination, bytes, bytes, bufferpoolGetLargeBufferPadding(pool));
        }
        /* The untransferred suffix is published before any reentrant callback. */
        if (! keepaliveserverSendFrame(t, l, frame, kKeepAliveServerFrameKindNormal) ||
            ! spliceframereaderIsAttached(&ls->reader))
        {
            lineUnref(l);
            return;
        }
        if (ls->write_active == NULL)
            ls->write_active = bufferqueuePopFront(&ls->write_reentry);
    }
    ls->write_draining = false;
    lineUnref(l);
}

void keepaliveserverConsumeUpstreamFrames(tunnel_t *t, line_t *l)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    lineRef(l);
    for (;;)
    {
        const uint8_t *header = spliceframereaderPeekHeader(&ls->reader);
        if (header == NULL)
            break;
        uint32_t network_length;
        sbufByteCopy(&network_length, header, sizeof(network_length));
        const uint32_t body_length = ntohl(network_length);
        const uint8_t  kind        = header[kKeepAliveServerFrameLengthSize];
        if (body_length < kKeepAliveServerFrameTypeSize || body_length > kKeepAliveServerMaxFrameBodyLength)
        {
            LOGW("KeepAliveServer: invalid keepalive frame length");
            keepaliveserverCloseLineFromProtocolError(t, l);
            lineUnref(l);
            return;
        }
        const uint32_t bytes = body_length - kKeepAliveServerFrameTypeSize;
        if (! spliceframereaderBodyReady(&ls->reader, bytes))
            break;
        bool alive = true;
        if (kind == kKeepAliveServerFrameKindNormal && bytes != 0)
        {
            sbuf_t *body = spliceframereaderTakeFrame(&ls->reader, bytes);
            alive = lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, body);
        }
        else
        {
            spliceframereaderDiscardFrame(&ls->reader, bytes);
            if (kind == kKeepAliveServerFrameKindPing)
                alive = keepaliveserverSendControlFrame(t, l, kKeepAliveServerFrameKindPong);
        }
        if (! alive || ! spliceframereaderIsAttached(&ls->reader))
        {
            lineUnref(l);
            return;
        }
    }
    /* Draining leaves an incomplete validated frame; retained capacity still needs a bound. */
    assert(spliceframereaderLength(&ls->reader) <
           kKeepAliveServerMaxPayloadChunkSize + kKeepAliveServerFramePrefixSize);
    if (! spliceframereaderEndDrain(&ls->reader))
    {
        LOGW("KeepAliveServer: incomplete frame storage limit exceeded");
        keepaliveserverCloseLineFromProtocolError(t, l);
        lineUnref(l);
        return;
    }
    lineUnref(l);
}

void keepaliveserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    keepaliveserverLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
}

void keepaliveserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    keepaliveserverLinestateDestroy(lineGetState(l, t));
    tunnelPrevDownStreamFinish(t, l);
}

void keepaliveserverCloseLineFromProtocolError(tunnel_t *t, line_t *l)
{
    lineRef(l);
    keepaliveserverLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
    if (lineIsAlive(l))
        tunnelPrevDownStreamFinish(t, l);
    lineUnref(l);
}
