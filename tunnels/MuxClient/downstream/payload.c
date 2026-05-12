#include "structure.h"

#include "loggers/network_logger.h"

static void muxclientCloseOwnedParentLineFromDownstreamPayload(tunnel_t *t, muxclient_tstate_t *ts, line_t *parent_l,
                                                               muxclient_lstate_t *parent_ls)
{
    wid_t wid = lineGetWID(parent_l);

    lineLock(parent_l);

    if (ts->unsatisfied_lines[wid] == parent_l)
    {
        ts->unsatisfied_lines[wid] = NULL;
    }

    muxclientLinestateDestroy(parent_ls);
    tunnelNextUpStreamFinish(t, parent_l);

    if (lineIsAlive(parent_l))
    {
        lineDestroy(parent_l);
    }

    lineUnlock(parent_l);
}

static sbuf_t *tryReadCompleteFrame(muxclient_lstate_t *parent_ls, mux_frame_t *frame)
{
    if (bufferstreamGetBufLen(&(parent_ls->read_stream)) < kMuxFrameLength)
    {
        return NULL;
    }

    bufferstreamViewBytesAt(&(parent_ls->read_stream), 0, (uint8_t *) frame, kMuxFrameLength);

    mux_length_t payload_length = be16toh(frame->length);
    cid_t        cid            = be32toh(frame->cid);

    size_t total_frame_size = (size_t) payload_length + (size_t) kMuxFrameLength;
    if (total_frame_size > bufferstreamGetBufLen(&(parent_ls->read_stream)))
    {
        return NULL;
    }

    frame->length = payload_length;
    frame->cid    = cid;

    return bufferstreamReadExact(&(parent_ls->read_stream), total_frame_size);
}

static muxclient_lstate_t *findChildByConnectionId(muxclient_lstate_t *parent_ls, uint32_t cid)
{
    muxclient_lstate_t *child_ls = parent_ls->child_next;
    while (child_ls)
    {
        if (child_ls->connection_id == cid)
        {
            return child_ls;
        }
        child_ls = child_ls->child_next;
    }
    return NULL;
}

static void moveChildToFront(muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    if (child_ls == parent_ls->child_next)
    {
        return;
    }

    if (child_ls->child_prev)
    {
        child_ls->child_prev->child_next = child_ls->child_next;
    }
    if (child_ls->child_next)
    {
        child_ls->child_next->child_prev = child_ls->child_prev;
    }

    child_ls->child_prev = NULL;
    child_ls->child_next = parent_ls->child_next;
    if (parent_ls->child_next)
    {
        parent_ls->child_next->child_prev = child_ls;
    }
    parent_ls->child_next = child_ls;
}

static bool handleCloseFrame(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                             muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    LOGD("MuxClient: DownStreamPayload: Close frame received, cid: %u", frame->cid);
    lineReuseBuffer(parent_l, frame_buffer);

    bool child_alive = muxclientFlushChildPending(t, parent_l, parent_ls, child_l, child_ls, true);
    if (! lineIsAlive(parent_l))
    {
        return false;
    }

    if (child_alive)
    {
        muxclientLeaveConnection(child_ls);
        muxclientLinestateDestroy(child_ls);
        tunnelPrevDownStreamFinish(t, child_l);
        if (! lineIsAlive(parent_l))
        {
            return false;
        }
    }

    if (muxclientCheckConnectionIsExhausted(ts, parent_ls) && parent_ls->children_count == 0)
    {
        muxclientCloseOwnedParentLineFromDownstreamPayload(t, ts, parent_l, parent_ls);
        return false;
    }
    return true;
}

static bool processFrameForChild(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                                 muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    switch (frame->flags)
    {
    case kMuxFlagOpen:
        LOGE("MuxClient: DownStreamPayload: Open frame received, cid: %u, but no Open flag should be sent to "
             "MuxClient node",
             frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        break;

    case kMuxFlagClose:
        if (! handleCloseFrame(t, parent_l, frame, frame_buffer, ts, parent_ls, child_ls))
        {
            return false;
        }
        break;

    case kMuxFlagFlowPause:
        // LOGD("MuxClient: DownStreamPayload: FlowPause frame received, cid: %u", frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        tunnelPrevDownStreamPause(t, child_l);
        break;

    case kMuxFlagFlowResume:
        // LOGD("MuxClient: DownStreamPayload: FlowResume frame received, cid: %u", frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        tunnelPrevDownStreamResume(t, child_l);
        break;

    case kMuxFlagData:
        // LOGD("MuxClient: DownStreamPayload: Data frame received, cid: %u", frame->cid);
        sbufShiftRight(frame_buffer, kMuxFrameLength);
        if (child_ls->paused)
        {
            return muxclientQueueChildPayload(t, parent_l, ts, parent_ls, child_ls, frame_buffer);
        }
        if (! withLineLockedWithBuf(child_l, tunnelPrevDownStreamPayload, t, frame_buffer))
        {
            return lineIsAlive(parent_l);
        }
        break;

    default:
        LOGD("MuxClient: DownStreamPayload: Unknown frame type received, cid: %u", frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        break;
    }
    return true;
}

static bool isOverFlow(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > kMaxMainChannelBufferSize)
    {
        LOGW("MuxClient: DownStreamPayload: Read stream overflow, size: %zu, limit: %zu", bufferstreamGetBufLen(read_stream),
             kMaxMainChannelBufferSize);
        return true;
    }
    return false;
}

static void handleOverFlow(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t *ts        = tunnelGetState(t);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    muxclient_lstate_t *child_ls = parent_ls->child_next;
    while (child_ls)
    {
        muxclient_lstate_t *temp    = child_ls->child_next;
        line_t             *child_l = child_ls->l;
        muxclientLeaveConnection(child_ls);
        muxclientLinestateDestroy(child_ls);
        tunnelPrevDownStreamFinish(t, child_l);
        child_ls = temp;
    }

    muxclientCloseOwnedParentLineFromDownstreamPayload(t, ts, parent_l, parent_ls);
}

void muxclientTunnelDownStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxclient_tstate_t *ts        = tunnelGetState(t);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    bufferstreamPush(&(parent_ls->read_stream), buf);

    if (isOverFlow(&(parent_ls->read_stream)))
    {
        handleOverFlow(t, parent_l);
        return;
    }

    while (true)
    {
        mux_frame_t frame        = {0};
        sbuf_t     *frame_buffer = tryReadCompleteFrame(parent_ls, &frame);

        if (! frame_buffer)
        {
            break;
        }

        muxclient_lstate_t *child_ls = findChildByConnectionId(parent_ls, frame.cid);
        if (! child_ls)
        {
            // LOGD("MuxClient: DownStreamPayload: No child line state found for cid: %u", frame.cid);
            lineReuseBuffer(parent_l, frame_buffer);
            continue;
        }

        moveChildToFront(parent_ls, child_ls);

        lineLock(parent_l);
        if (! processFrameForChild(t, parent_l, &frame, frame_buffer, ts, parent_ls, child_ls))
        {
            lineUnlock(parent_l);
            return;
        }

        if (! lineIsAlive(parent_l))
        {
            LOGD("MuxClient: DownStreamPayload: Parent line is not alive, stopping processing for cid: %u", frame.cid);
            lineUnlock(parent_l);
            return;
        }
        lineUnlock(parent_l);
    }
}
