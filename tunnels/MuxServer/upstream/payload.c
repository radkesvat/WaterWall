#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *tryReadCompleteFrame(muxserver_lstate_t *parent_ls, mux_frame_t *frame)
{
    if (bufferstreamLen(&(parent_ls->read_stream)) < kMuxFrameLength)
    {
        return NULL;
    }

    bufferstreamViewBytesAt(&(parent_ls->read_stream), 0, (uint8_t *) frame, kMuxFrameLength);

    size_t total_frame_size = (size_t) frame->length + (size_t) kMuxFrameLength;
    if (total_frame_size > bufferstreamLen(&(parent_ls->read_stream)))
    {
        return NULL;
    }

    return bufferstreamReadExact(&(parent_ls->read_stream), total_frame_size);
}

static bool handleOpenFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, mux_frame_t *frame,
                            sbuf_t *frame_buffer)
{
    bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
    LOGD("MuxServer: UpStreamPayload: Open frame received, cid: %u", frame->cid);

    line_t             *child_l      = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(parent_l));
    muxserver_lstate_t *new_child_ls = lineGetState(child_l, t);
    muxserverLinestateInitialize(new_child_ls, child_l, true, frame->cid);
    muxserverJoinConnection(parent_ls, new_child_ls);
    lineLock(child_l);
    tunnelNextUpStreamInit(t, child_l);

    if (! lineIsAlive(child_l))
    {
        LOGD("MuxServer: UpStreamPayload: child line is closed when opening line %u", frame->cid);
        lineUnlock(child_l);
        return false;
    }
    lineUnlock(child_l);
    return true;
}

static muxserver_lstate_t *findChildByConnectionId(muxserver_lstate_t *parent_ls, uint32_t cid)
{
    muxserver_lstate_t *child_ls = parent_ls->child_next;
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

static void moveChildToFront(muxserver_lstate_t *parent_ls, muxserver_lstate_t *child_ls)
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

static void processFrameForChild(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                                 muxserver_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    switch (frame->flags)
    {
    case kMuxFlagClose:
        LOGD("MuxServer: UpStreamPayload: Close frame received, cid: %u", frame->cid);
        bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
        muxserverLeaveConnection(child_ls);
        muxserverLinestateDestroy(child_ls);
        tunnelNextUpStreamFinish(t, child_l);
        lineDestroy(child_l);
        break;

    case kMuxFlagFlowPause:
        // LOGD("MuxServer: UpStreamPayload: FlowPause frame received, cid: %u", frame->cid);
        bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
        tunnelNextUpStreamPause(t, child_l);
        break;

    case kMuxFlagFlowResume:
        // LOGD("MuxServer: UpStreamPayload: FlowResume frame received, cid: %u", frame->cid);
        bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
        tunnelNextUpStreamResume(t, child_l);
        break;

    case kMuxFlagData:
        // LOGD("MuxServer: UpStreamPayload: Data frame received, cid: %u", frame->cid);
        sbufShiftRight(frame_buffer, kMuxFrameLength);
        tunnelNextUpStreamPayload(t, child_l, frame_buffer);
        break;

    default:
        // LOGD("MuxServer: UpStreamPayload: Unknown frame type received, cid: %u", frame->cid);
        bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
        break;
    }
}

static bool isOverFlow(buffer_stream_t *read_stream)
{
    if (bufferstreamLen(read_stream) > kMaxMainChannelBufferSize)
    {
        LOGW("MuxServer: UpStreamPayload: Read stream overflow, size: %zu, limit: %zu", bufferstreamLen(read_stream),
             kMaxMainChannelBufferSize);
        return true;
    }
    return false;
}

static void handleOverFlow(tunnel_t *t, line_t *parent_l)
{
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);
    muxserver_lstate_t *child_ls  = parent_ls->child_next;

    while (child_ls)
    {
        muxserver_lstate_t *temp    = child_ls->child_next;
        line_t             *child_l = child_ls->l;
        muxserverLeaveConnection(child_ls);
        muxserverLinestateDestroy(child_ls);
        tunnelNextUpStreamFinish(t, child_l);
        lineDestroy(child_l);
        child_ls = temp;
    }

    muxserverLinestateDestroy(parent_ls);

    tunnelPrevDownStreamFinish(t, parent_l);
}

void muxserverTunnelUpStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

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

        if (frame.flags == kMuxFlagOpen)
        {
            if (handleOpenFrame(t, parent_l, parent_ls, &frame, frame_buffer))
            {
                continue;
            }
            continue;
        }

        muxserver_lstate_t *child_ls = findChildByConnectionId(parent_ls, frame.cid);
        if (! child_ls)
        {
            // LOGD("MuxServer: UpStreamPayload: No child line state found for cid: %u", frame.cid);
            bufferpoolReuseBuffer(lineGetBufferPool(parent_l), frame_buffer);
            continue;
        }

        moveChildToFront(parent_ls, child_ls);

        lineLock(parent_l);
        processFrameForChild(t, parent_l, &frame, frame_buffer, child_ls);

        if (! lineIsAlive(parent_l))
        {
            LOGD("MuxServer: UpStreamPayload: Parent line is not alive, stopping processing for cid: %u", frame.cid);
            lineUnlock(parent_l);
            return;
        }
        lineUnlock(parent_l);
    }
}
