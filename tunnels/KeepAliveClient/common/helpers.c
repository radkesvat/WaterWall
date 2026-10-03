#include "structure.h"

#include "loggers/network_logger.h"

static bool keepaliveclientIsPacketLine(tunnel_t *t, line_t *l)
{
    return tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l);
}

static bool keepaliveclientSendFrame(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t kind)
{
    const uint32_t length = sbufGetLength(buf);
    assert(length <= kKeepAliveMaxPayloadChunkSize);
    assert(sbufGetLeftCapacity(buf) >= kKeepAliveFramePrefixSize);
    /* Only the real left padding is written, including for a private-pipe body. */
    sbufShiftLeft(buf, kKeepAliveFramePrefixSize);
    uint8_t *header         = sbufGetMutablePtr(buf);
    uint32_t network_length = htonl(length + kKeepAliveFrameTypeSize);
    sbufByteCopy(header, &network_length, sizeof(network_length));
    header[kKeepAliveFrameLengthSize] = kind;
    return lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

static bool keepaliveclientSendControlFrame(tunnel_t *t, line_t *l, uint8_t kind)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);
    return keepaliveclientSendFrame(t, l, buf, kind);
}

static bool keepaliveclientCheckPongDeadline(tunnel_t *t, line_t *l, uint64_t now)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    if (ls->awaiting_pong && now >= ls->pong_deadline_ms)
    {
        keepaliveclient_tstate_t *ts = tunnelGetState(t);
        LOGW("KeepAliveClient: pong timed out (tolerance=%u ms), closing connection", ts->tolerance_ms);
        keepaliveclientCloseLineFromProtocolError(t, l);
        return false;
    }
    return true;
}

bool keepaliveclientSendNormalFrameUpstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->read_stream != NULL);
    const uint32_t length = sbufGetLength(buf);
    if (length == 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }
    if (keepaliveclientIsPacketLine(t, l) && length > kMaxAllowedPacketLength - kKeepAliveFramePrefixSize)
    {
        LOGE("KeepAliveClient: packet payload exceeds kMaxAllowedPacketLength after framing");
        lineReuseBuffer(l, buf);
        return true;
    }
    if (ls->write_draining)
    {
        const size_t pending =
            bufferqueueGetBufLen(&ls->write_reentry) + (ls->write_active != NULL ? sbufGetLength(ls->write_active) : 0);
        if (pending > kKeepAliveMaxReentryBytes || length > kKeepAliveMaxReentryBytes - pending ||
            bufferqueueGetBufCount(&ls->write_reentry) + (ls->write_active != NULL) >= kKeepAliveMaxReentryBuffers ||
            ! bufferqueueTryPushBack(&ls->write_reentry, &buf))
        {
            lineReuseBuffer(l, buf);
            keepaliveclientCloseLineFromProtocolError(t, l);
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
        const uint32_t bytes  = min(sbufGetLength(source), (uint32_t) kKeepAliveMaxPayloadChunkSize);
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
        if (! keepaliveclientSendFrame(t, l, frame, kKeepAliveFrameKindNormal) || ls->read_stream == NULL)
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

bool keepaliveclientConsumeDownstreamFrames(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
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
        const uint8_t  kind        = header[kKeepAliveFrameLengthSize];
        if (body_length < kKeepAliveFrameTypeSize || body_length > kKeepAliveMaxFrameBodyLength)
        {
            LOGW("KeepAliveClient: invalid keepalive frame length");
            keepaliveclientCloseLineFromProtocolError(t, l);
            lineUnref(l);
            return false;
        }
        const uint32_t bytes = body_length - kKeepAliveFrameTypeSize;
        if (splicestreamBodyBytes(ls->read_stream) < bytes)
            break;
        buffer_pool_t *pool = lineGetBufferPool(l);
        sbuf_t *destination = bytes != 0 && tunnelGetChain(t)->supports_splice ? bufferpoolGetSpliceBuffer(pool) : NULL;
        sbuf_t *body        = splicestreamMoveFrame(ls->read_stream, destination, bytes);
        bool    alive       = true;
        if (kind == kKeepAliveFrameKindNormal && bytes != 0)
            alive = lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, body);
        else
        {
            lineReuseBuffer(l, body);
            if (kind == kKeepAliveFrameKindPing)
                alive = keepaliveclientSendControlFrame(t, l, kKeepAliveFrameKindPong);
            else if (kind == kKeepAliveFrameKindPong && bytes == 0 && ts->sensitive_mode && ls->awaiting_pong)
            {
                const uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
                alive              = keepaliveclientCheckPongDeadline(t, l, now);
                if (alive)
                {
                    ls->awaiting_pong    = false;
                    ls->pong_deadline_ms = 0;
                }
            }
        }
        if (! alive || ls->read_stream == NULL)
        {
            lineUnref(l);
            return false;
        }
    }
    /* A large delivery may contain many complete frames. Bound only what remains. */
    if (splicestreamCharge(ls->read_stream) > kKeepAliveReadChargeLimit)
        discard splicestreamCompact(ls->read_stream);
    if (splicestreamLength(ls->read_stream) > kKeepAliveReadOverflowLimit ||
        splicestreamCharge(ls->read_stream) > kKeepAliveReadChargeLimit)
    {
        LOGW("KeepAliveClient: incomplete frame storage limit exceeded");
        keepaliveclientCloseLineFromProtocolError(t, l);
        lineUnref(l);
        return false;
    }
    ls->read_draining = false;
    lineUnref(l);
    return true;
}

void keepaliveclientTrackLine(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);

    mutexLock(&ts->lines_mutex);

    ls->tracked_prev = NULL;
    ls->tracked_next = ts->lines_head;
    if (ts->lines_head != NULL)
    {
        ts->lines_head->tracked_prev = ls;
    }
    ts->lines_head = ls;

    mutexUnlock(&ts->lines_mutex);
}

void keepaliveclientUntrackLine(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);

    mutexLock(&ts->lines_mutex);

    if (ls->tracked_prev != NULL)
    {
        ls->tracked_prev->tracked_next = ls->tracked_next;
    }
    else if (ts->lines_head == ls)
    {
        ts->lines_head = ls->tracked_next;
    }

    if (ls->tracked_next != NULL)
    {
        ls->tracked_next->tracked_prev = ls->tracked_prev;
    }

    ls->tracked_prev = NULL;
    ls->tracked_next = NULL;
    mutexUnlock(&ts->lines_mutex);
}

void keepaliveclientWorkerTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL)
    {
        return;
    }

    keepaliveclient_tstate_t *ts    = tunnelGetState(t);
    keepaliveclient_lstate_t *it    = NULL;
    line_t                  **lines = NULL;
    size_t                    count = 0;
    size_t                    index = 0;
    const wid_t               wid   = getLoopEventWorkerWID(weventGetLoop(timer));

    mutexLock(&ts->lines_mutex);

    for (it = ts->lines_head; it != NULL; it = it->tracked_next)
    {
        if (it->wid == wid && it->line != NULL)
        {
            count += 1;
        }
    }

    if (count > 0)
    {
        if (UNLIKELY(count > SIZE_MAX / sizeof(*lines)))
        {
            LOGW("KeepAliveClient: too many tracked lines to snapshot periodic pings on worker %d", (int) wid);
            mutexUnlock(&ts->lines_mutex);
            return;
        }

        lines = memoryAllocate(sizeof(line_t *) * count);
        if (UNLIKELY(lines == NULL))
        {
            LOGW("KeepAliveClient: failed to snapshot %zu tracked line(s) for periodic pings on worker %d",
                 count,
                 (int) wid);
            mutexUnlock(&ts->lines_mutex);
            return;
        }

        for (it = ts->lines_head; it != NULL; it = it->tracked_next)
        {
            if (it->wid == wid && it->line != NULL)
            {
                /* A ping callback for one line may synchronously close another
                 * tracked line. Retain every snapshot entry while the registry
                 * lock still proves it is live, so later entries remain
                 * physically valid after such re-entrant removal. */
                lineRef(it->line);
                lines[index++] = it->line;
            }
        }
    }

    mutexUnlock(&ts->lines_mutex);

    for (size_t i = 0; i < count; ++i)
    {
        if (lineIsAlive(lines[i]))
        {
            discard keepaliveclientSendPingFrame(t, lines[i]);
        }

        lineUnref(lines[i]);
    }

    if (lines != NULL)
    {
        memoryFree(lines);
    }
}

bool keepaliveclientSendPingFrame(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    if (! ls->established)
        return true;
    const uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
    if (ts->sensitive_mode)
    {
        if (! keepaliveclientCheckPongDeadline(t, l, now))
            return false;
        if (ls->awaiting_pong)
            return true;
    }
    if (now < ls->next_ping_at_ms)
        return true;
    ls->next_ping_at_ms = now + ts->ping_interval_ms;
    if (ts->sensitive_mode)
    {
        /* Publish before sending: the callback can deliver its pong inline. */
        ls->awaiting_pong    = true;
        ls->pong_deadline_ms = now + ts->tolerance_ms;
    }
    return keepaliveclientSendControlFrame(t, l, kKeepAliveFrameKindPing);
}

void keepaliveclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    if (! ls->established)
    {
        ls->established     = true;
        ls->next_ping_at_ms = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l))) + ts->ping_interval_ms;
    }
    tunnelPrevDownStreamEst(t, l);
}

void keepaliveclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamPause(t, l);
}

void keepaliveclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamResume(t, l);
}

void keepaliveclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamPause(t, l);
}

void keepaliveclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamResume(t, l);
}

void keepaliveclientCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    keepaliveclientUntrackLine(t, l);
    keepaliveclientLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
}

void keepaliveclientCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    keepaliveclientUntrackLine(t, l);
    keepaliveclientLinestateDestroy(lineGetState(l, t));
    tunnelPrevDownStreamFinish(t, l);
}

void keepaliveclientCloseLineFromProtocolError(tunnel_t *t, line_t *l)
{
    lineRef(l);
    keepaliveclientUntrackLine(t, l);
    keepaliveclientLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
    if (lineIsAlive(l))
        tunnelPrevDownStreamFinish(t, l);
    lineUnref(l);
}
