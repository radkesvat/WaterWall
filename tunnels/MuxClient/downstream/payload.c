#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *tryReadCompleteFrame(muxclient_lstate_t *parent_ls, mux_frame_t *frame)
{
    if (bufferstreamLen(parent_&(ls->read_stream)) < kMuxFrameLength)
    {
        return NULL;
    }

    bufferstreamViewBytesAt(parent_&(ls->read_stream), 0, (uint8_t *) frame, kMuxFrameLength);

    size_t total_frame_size = (size_t) frame->length + (size_t) kMuxFrameLength;
    if (total_frame_size > bufferstreamLen(parent_&(ls->read_stream)))
    {
        return NULL;
    }

    return bufferstreamReadExact(parent_&(ls->read_stream), total_frame_size);
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
    wid_t   wid     = lineGetWID(parent_l);

    LOGD("MuxClient: DownStreamPayload: Close frame received, cid: %u", frame->cid);
    bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
    muxclientLeaveConnection(child_ls);
    muxclientLinestateDestroy(child_ls);
    tunnelPrevDownStreamFinish(t, child_l);

    if (muxclientCheckConnectionIsExhausted(ts, parent_ls) && parent_ls->children_count == 0)
    {
        if (ts->unsatisfied_lines[wid] == parent_l)
        {
            ts->unsatisfied_lines[wid] = NULL;
        }
        muxclientLinestateDestroy(parent_ls);
        tunnelNextUpStreamFinish(t, parent_l);
        lineDestroy(parent_l);
        return false;
    }
    return true;
}

static void processFrameForChild(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                                 muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    switch (frame->flags)
    {
    case kMuxFlagOpen:
        LOGE("MuxClient: DownStreamPayload: Open frame received, cid: %u, but no Open flag should be sent to "
             "MuxClient node",
             frame->cid);
        bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
        break;

    case kMuxFlagClose:
        if (! handleCloseFrame(t, parent_l, frame, frame_buffer, ts, parent_ls, child_ls))
        {
            return;
        }
        break;

    case kMuxFlagFlowPause:
        // LOGD("MuxClient: DownStreamPayload: FlowPause frame received, cid: %u", frame->cid);
        bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
        tunnelPrevDownStreamPause(t, child_l);
        break;

    case kMuxFlagFlowResume:
        // LOGD("MuxClient: DownStreamPayload: FlowResume frame received, cid: %u", frame->cid);
        bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
        tunnelPrevDownStreamResume(t, child_l);
        break;

    case kMuxFlagData:
        // LOGD("MuxClient: DownStreamPayload: Data frame received, cid: %u", frame->cid);
        sbufShiftRight(frame_buffer, kMuxFrameLength);
        tunnelPrevDownStreamPayload(t, child_l, frame_buffer);
        break;

    default:
        LOGD("MuxClient: DownStreamPayload: Unknown frame type received, cid: %u", frame->cid);
        bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
        break;
    }
}

static bool isOverFlow(buffer_stream_t *read_stream)
{
    if (bufferstreamLen(read_stream) > kMaxMainChannelBufferSize)
    {
        LOGW("MuxClient: DownStreamPayload: Read stream overflow, size: %zu, limit: %zu", bufferstreamLen(read_stream),
             kMaxMainChannelBufferSize);
        return false;
    }
    return true;
}

static void handleOverFlow(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t *ts        = tunnelGetState(t);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
    if (ts->unsatisfied_lines[lineGetWID(parent_l)] == parent_l)
    {
        ts->unsatisfied_lines[lineGetWID(parent_l)] = NULL;
    }

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

    muxclientLinestateDestroy(parent_ls);
    tunnelNextUpStreamFinish(t, parent_l);
    lineDestroy(parent_l);
}

void muxclientTunnelDownStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxclient_tstate_t *ts        = tunnelGetState(t);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    bufferstreamPush(parent_&(ls->read_stream), buf);

    if (! isOverFlow(parent_&(ls->read_stream)))
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
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            continue;
        }

        moveChildToFront(parent_ls, child_ls);

        lineLock(parent_l);
        processFrameForChild(t, parent_l, &frame, frame_buffer, ts, parent_ls, child_ls);

        if (! lineIsAlive(parent_l))
        {
            LOGD("MuxClient: DownStreamPayload: Parent line is not alive, stopping processing for cid: %u", frame.cid);
            lineUnlock(parent_l);
            return;
        }
        lineUnlock(parent_l);
    }
}
