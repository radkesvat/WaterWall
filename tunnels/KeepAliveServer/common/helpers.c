#include "structure.h"

#include "loggers/network_logger.h"

static bool keepaliveserverIsPacketLine(tunnel_t *t, line_t *l)
{
    return tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l);
}

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
    assert(! ((keepaliveserver_lstate_t *) lineGetState(l, t))->write_paused);
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);
    return keepaliveserverSendFrame(t, l, buf, kind);
}

static bool keepaliveserverDrainPongs(tunnel_t *t, line_t *l)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    if (ls->pong_draining)
        return true;
    lineRef(l);
    ls->pong_draining = true;
    while (! ls->write_paused && ls->pending_pongs != 0)
    {
        --ls->pending_pongs;
        if (! keepaliveserverSendControlFrame(t, l, kKeepAliveServerFrameKindPong) || ls->read_stream == NULL)
        {
            lineUnref(l);
            return false;
        }
    }
    ls->pong_draining = false;
    lineUnref(l);
    return true;
}

static bool keepaliveserverSendPongFrame(tunnel_t *t, line_t *l)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    if (ls->pending_pongs >= kKeepAliveServerMaxPendingPongs)
    {
        LOGW("KeepAliveServer: pending pong limit exceeded");
        keepaliveserverCloseLineFromProtocolError(t, l);
        return false;
    }
    ++ls->pending_pongs;
    return keepaliveserverDrainPongs(t, l);
}

void keepaliveserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    ((keepaliveserver_lstate_t *) lineGetState(l, t))->write_paused = true;
    tunnelNextUpStreamPause(t, l);
}

void keepaliveserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    ((keepaliveserver_lstate_t *) lineGetState(l, t))->write_paused = false;
    if (! lineCallWithRef(l, tunnelNextUpStreamResume, t))
        return;
    if (((keepaliveserver_lstate_t *) lineGetState(l, t))->read_stream != NULL)
        discard keepaliveserverDrainPongs(t, l);
}

bool keepaliveserverSendNormalFrameDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->read_stream != NULL);
    const uint32_t length = sbufGetLength(buf);
    if (length == 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }
    if (keepaliveserverIsPacketLine(t, l) && length > kMaxAllowedPacketLength - kKeepAliveServerFramePrefixSize)
    {
        LOGE("KeepAliveServer: packet payload exceeds kMaxAllowedPacketLength after framing");
        lineReuseBuffer(l, buf);
        return true;
    }
    if (ls->write_draining)
    {
        const size_t pending =
            bufferqueueGetBufLen(&ls->write_reentry) + (ls->write_active != NULL ? sbufGetLength(ls->write_active) : 0);
        if (pending > kKeepAliveServerMaxReentryBytes || length > kKeepAliveServerMaxReentryBytes - pending ||
            bufferqueueGetBufCount(&ls->write_reentry) + (ls->write_active != NULL) >=
                kKeepAliveServerMaxReentryBuffers ||
            ! bufferqueueTryPushBack(&ls->write_reentry, &buf))
        {
            lineReuseBuffer(l, buf);
            keepaliveserverCloseLineFromProtocolError(t, l);
            return false;
        }
        return true;
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
        if (! keepaliveserverSendFrame(t, l, frame, kKeepAliveServerFrameKindNormal) || ls->read_stream == NULL)
        {
            lineUnref(l);
            return false;
        }
        if (ls->write_active == NULL)
            ls->write_active = bufferqueuePopFront(&ls->write_reentry);
    }
    ls->write_draining = false;
    lineUnref(l);
    return true;
}

bool keepaliveserverConsumeUpstreamFrames(tunnel_t *t, line_t *l)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    if (ls->read_draining)
        return true;
    ls->read_draining = true;
    lineRef(l);
    for (;;)
    {
        const uint8_t *header = splicestreamPeekHeader(ls->read_stream);
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
            return false;
        }
        const uint32_t bytes = body_length - kKeepAliveServerFrameTypeSize;
        if (splicestreamBodyBytes(ls->read_stream) < bytes)
            break;
        buffer_pool_t *pool = lineGetBufferPool(l);
        sbuf_t *destination = bytes != 0 && tunnelGetChain(t)->supports_splice ? bufferpoolGetSpliceBuffer(pool) : NULL;
        sbuf_t *body        = splicestreamMoveFrame(ls->read_stream, destination, bytes);
        bool    alive       = true;
        if (kind == kKeepAliveServerFrameKindNormal && bytes != 0)
            alive = lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, body);
        else
        {
            lineReuseBuffer(l, body);
            if (kind == kKeepAliveServerFrameKindPing)
                alive = keepaliveserverSendPongFrame(t, l);
        }
        if (! alive || ls->read_stream == NULL)
        {
            lineUnref(l);
            return false;
        }
    }
    /* A large delivery may contain many complete frames. Bound only what remains. */
    if (splicestreamCharge(ls->read_stream) > kKeepAliveServerReadChargeLimit)
        discard splicestreamCompact(ls->read_stream);
    if (splicestreamLength(ls->read_stream) > kKeepAliveServerReadOverflowLimit ||
        splicestreamCharge(ls->read_stream) > kKeepAliveServerReadChargeLimit)
    {
        LOGW("KeepAliveServer: incomplete frame storage limit exceeded");
        keepaliveserverCloseLineFromProtocolError(t, l);
        lineUnref(l);
        return false;
    }
    ls->read_draining = false;
    lineUnref(l);
    return true;
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
