#include "structure.h"

#include "loggers/network_logger.h"

static void keepaliveclientPingExpired(local_idle_item_t *item);
static void keepaliveclientPongDeadlineExpired(local_idle_item_t *item);

static local_idle_item_t *keepaliveclientCreateIdleItem(tunnel_t *t, line_t *l, local_idle_item_t **slot,
                                                        LocalIdleExpireCallBack callback, uint64_t age_ms)
{
    assert(lineIsOnCurrentEventWorker(l));
    assert(*slot == NULL);
    keepaliveclient_tstate_t *ts    = tunnelGetState(t);
    local_idle_table_t       *table = ts->worker_states[lineGetWID(l)].idle_table;
    local_idle_item_t        *item =
        localidletableCreateItem(table, (hash_t) (uintptr_t) slot, lineGetState(l, t), callback, age_ms);
    if (UNLIKELY(item == NULL))
    {
        LOGF("KeepAliveClient: duplicate idle item for a line");
        abortProgramNow(1);
    }
    return item;
}

static void keepaliveclientRemoveIdleItem(local_idle_item_t **slot)
{
    local_idle_item_t *item = *slot;
    if (item == NULL)
        return;
    *slot              = NULL;
    const bool removed = localidletableRemoveIdleItem(item->table, item);
    assert(removed);
    discard removed;
}

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
    assert(! ((keepaliveclient_lstate_t *) lineGetState(l, t))->write_paused);
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);
    return keepaliveclientSendFrame(t, l, buf, kind);
}

static bool keepaliveclientDrainPongs(tunnel_t *t, line_t *l)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    if (ls->pong_draining)
        return true;
    lineRef(l);
    ls->pong_draining = true;
    while (! ls->write_paused && ls->pending_pongs != 0)
    {
        --ls->pending_pongs;
        if (! keepaliveclientSendControlFrame(t, l, kKeepAliveFrameKindPong) || ls->read_stream == NULL)
        {
            lineUnref(l);
            return false;
        }
    }
    ls->pong_draining = false;
    lineUnref(l);
    return true;
}

static bool keepaliveclientSendPongFrame(tunnel_t *t, line_t *l)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    if (ls->pending_pongs >= kKeepAliveMaxPendingPongs)
    {
        LOGW("KeepAliveClient: pending pong limit exceeded");
        keepaliveclientCloseLineFromProtocolError(t, l);
        return false;
    }
    ++ls->pending_pongs;
    return keepaliveclientDrainPongs(t, l);
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
                alive = keepaliveclientSendPongFrame(t, l);
            else if (kind == kKeepAliveFrameKindPong && bytes == 0 && ts->sensitive_mode && ls->awaiting_pong)
            {
                const uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
                alive              = keepaliveclientCheckPongDeadline(t, l, now);
                if (alive)
                {
                    keepaliveclientRemoveIdleItem(&ls->pong_deadline_item);
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
    assert(lineIsOnCurrentEventWorker(l));
    keepaliveclient_tstate_t       *ts    = tunnelGetState(t);
    keepaliveclient_lstate_t       *ls    = lineGetState(l, t);
    keepaliveclient_worker_state_t *state = &ts->worker_states[lineGetWID(l)];

    assert(state->active_lines < SIZE_MAX);
    ls->tunnel = t;
    ++state->active_lines;
}

void keepaliveclientUntrackLine(tunnel_t *t, line_t *l)
{
    assert(lineIsOnCurrentEventWorker(l));
    keepaliveclient_tstate_t       *ts    = tunnelGetState(t);
    keepaliveclient_lstate_t       *ls    = lineGetState(l, t);
    keepaliveclient_worker_state_t *state = &ts->worker_states[lineGetWID(l)];

    keepaliveclientRemoveIdleItem(&ls->ping_item);
    keepaliveclientRemoveIdleItem(&ls->pong_deadline_item);
    assert(state->active_lines != 0);
    --state->active_lines;
    if (state->quiesced && state->active_lines == 0 && state->idle_table != NULL)
    {
        /* Owner drain may run after this tunnel's lifecycle hook. */
        localidletableDestroy(state->idle_table);
        state->idle_table = NULL;
    }
}

bool keepaliveclientSendPingFrame(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    if (! ls->established || ts->worker_states[lineGetWID(l)].quiesced)
        return true;
    const uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
    if (ts->sensitive_mode)
    {
        if (! keepaliveclientCheckPongDeadline(t, l, now))
            return false;
        if (ls->awaiting_pong)
            return true;
    }
    if (now < ls->next_ping_at_ms || ls->write_paused || ls->write_draining || ls->pong_draining ||
        ls->pending_pongs != 0)
        return true;
    ls->next_ping_at_ms = now + ts->ping_interval_ms;
    if (ts->sensitive_mode)
    {
        /* Publish before sending: the callback can deliver its pong inline. */
        ls->awaiting_pong      = true;
        ls->pong_deadline_ms   = now + ts->tolerance_ms;
        ls->pong_deadline_item = keepaliveclientCreateIdleItem(
            t, l, &ls->pong_deadline_item, keepaliveclientPongDeadlineExpired, ts->tolerance_ms);
    }
    return keepaliveclientSendControlFrame(t, l, kKeepAliveFrameKindPing);
}

static void keepaliveclientPingExpired(local_idle_item_t *item)
{
    keepaliveclient_lstate_t *ls = item->userdata;
    line_t                   *l  = ls->line;
    tunnel_t                 *t  = ls->tunnel;
    assert(lineIsOnCurrentEventWorker(l));
    /* The payload callback may close this line or another due table item. */
    lineRef(l);
    if (! keepaliveclientSendPingFrame(t, l))
    {
        lineUnref(l);
        return;
    }
    if (ls->read_stream != NULL)
    {
        const uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
        const uint64_t age = ls->next_ping_at_ms > now ? ls->next_ping_at_ms - now : kKeepAlivePingRetryMs;
        /* Retry without moving the due time or an outstanding reply deadline. */
        localidletableKeepIdleItemForAtleast(item->table, item, age);
    }
    lineUnref(l);
}

static void keepaliveclientPongDeadlineExpired(local_idle_item_t *item)
{
    keepaliveclient_lstate_t *ls = item->userdata;
    tunnel_t                 *t  = ls->tunnel;
    line_t                   *l  = ls->line;
    assert(lineIsOnCurrentEventWorker(l));
    assert(ls->awaiting_pong);
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    LOGW("KeepAliveClient: pong timed out (tolerance=%u ms), closing connection", ts->tolerance_ms);
    keepaliveclientCloseLineFromProtocolError(t, l);
}

void keepaliveclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    if (! ls->established)
    {
        keepaliveclient_worker_state_t *state = &ts->worker_states[lineGetWID(l)];
        if (! state->quiesced && state->idle_table == NULL)
            state->idle_table = localIdleTableCreate(getWorkerLoop(lineGetWID(l)));
        /* Table creation refreshes the loop clock while installing its timer. */
        ls->established     = true;
        ls->next_ping_at_ms = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l))) + ts->ping_interval_ms;
        if (! state->quiesced)
            ls->ping_item =
                keepaliveclientCreateIdleItem(t, l, &ls->ping_item, keepaliveclientPingExpired, ts->ping_interval_ms);
    }
    tunnelPrevDownStreamEst(t, l);
}

void keepaliveclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    ((keepaliveclient_lstate_t *) lineGetState(l, t))->write_paused = true;
    tunnelPrevDownStreamPause(t, l);
}

void keepaliveclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    ((keepaliveclient_lstate_t *) lineGetState(l, t))->write_paused = false;
    if (! lineCallWithRef(l, tunnelPrevDownStreamResume, t))
        return;
    if (((keepaliveclient_lstate_t *) lineGetState(l, t))->read_stream != NULL)
        discard keepaliveclientDrainPongs(t, l);
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
