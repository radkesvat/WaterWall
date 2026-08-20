#include "structure.h"

#include "loggers/network_logger.h"

static muxserver_lstate_t *findChildByConnectionId(muxserver_lstate_t *parent_ls, uint32_t cid);

static bool handleOpenFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, mux_frame_t *frame,
                            sbuf_t *frame_buffer)
{
    lineReuseBuffer(parent_l, frame_buffer);
    LOGD("MuxServer: UpStreamPayload: Open frame received, cid: %u", frame->cid);

    muxserver_lstate_t *existing = findChildByConnectionId(parent_ls, frame->cid);
    if (existing != NULL)
    {
        if (existing->close_state == kMuxServerChildCloseOpen)
        {
            LOGW("MuxServer: UpStreamPayload: Duplicate Open frame ignored, cid: %u", frame->cid);
        }
        return true;
    }

    line_t             *child_l      = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(parent_l));
    muxserver_lstate_t *new_child_ls = lineGetState(child_l, t);
    muxserverLinestateInitialize(new_child_ls, child_l, true, frame->cid);
    muxserverJoinConnection(parent_ls, new_child_ls);

    lineLock(parent_l);
    discard withLineLocked(child_l, tunnelNextUpStreamInit, t);
    bool    parent_alive = lineIsAlive(parent_l);
    lineUnlock(parent_l);
    return parent_alive;
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

static bool processFrameForChild(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                                 muxserver_tstate_t *ts, muxserver_lstate_t *parent_ls, muxserver_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    if (child_ls->close_state != kMuxServerChildCloseOpen)
    {
        lineReuseBuffer(parent_l, frame_buffer);
        return true;
    }

    switch (frame->flags)
    {
    case kMuxFlagClose:
        LOGD("MuxServer: UpStreamPayload: Close frame received, cid: %u", frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        if (! muxserverBeginPeerCloseDrain(t, parent_l, ts, parent_ls, child_ls))
        {
            return false;
        }
        break;

    case kMuxFlagFlowPause:
        // LOGD("MuxServer: UpStreamPayload: FlowPause frame received, cid: %u", frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        if (! muxserverPauseChildSource(t, parent_l, child_ls, true, false))
        {
            return false;
        }
        break;

    case kMuxFlagFlowResume:
        // LOGD("MuxServer: UpStreamPayload: FlowResume frame received, cid: %u", frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        if (! muxserverResumeChildSource(t, parent_l, child_ls, true, false))
        {
            return false;
        }
        break;

    case kMuxFlagData:
        // LOGD("MuxServer: UpStreamPayload: Data frame received, cid: %u", frame->cid);
        sbufShiftRight(frame_buffer, kMuxFrameLength);
        if (child_ls->paused)
        {
            return muxserverQueueChildPayload(t, parent_l, ts, parent_ls, child_ls, frame_buffer);
        }
        if (! withLineLockedWithBuf(child_l, tunnelNextUpStreamPayload, t, frame_buffer))
        {
            return lineIsAlive(parent_l);
        }
        break;

    default:
        // LOGD("MuxServer: UpStreamPayload: Unknown frame type received, cid: %u", frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        break;
    }
    return true;
}

static bool isOverFlow(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > kMaxMainChannelBufferSize)
    {
        LOGW("MuxServer: UpStreamPayload: Read stream overflow, size: %zu, limit: %zu",
             bufferstreamGetBufLen(read_stream),
             kMaxMainChannelBufferSize);
        return true;
    }
    return false;
}

static void handleOverFlow(tunnel_t *t, line_t *parent_l)
{
    muxserverHandleParentLoss(t, parent_l, true);
}

void muxserverTunnelUpStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxserver_tstate_t *ts        = tunnelGetState(t);
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

    if (parent_ls->parent_finishing)
    {
        lineReuseBuffer(parent_l, buf);
        return;
    }

    bufferstreamPush(&(parent_ls->read_stream), buf);

    while (true)
    {
        mux_frame_t frame        = {0};
        sbuf_t     *frame_buffer = muxReadCompleteFrame(&parent_ls->read_stream, &frame);

        if (! frame_buffer)
        {
            break;
        }

        if (frame.flags == kMuxFlagOpen)
        {
            if (! handleOpenFrame(t, parent_l, parent_ls, &frame, frame_buffer))
            {
                // The child Init was re-entrant and tore down the parent line (and its
                // line state). Both parent_l and parent_ls are now invalid, so we must
                // stop touching them immediately instead of looping back.
                return;
            }
            continue;
        }

        muxserver_lstate_t *child_ls = findChildByConnectionId(parent_ls, frame.cid);
        if (! child_ls)
        {
            // LOGD("MuxServer: UpStreamPayload: No child line state found for cid: %u", frame.cid);
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
            LOGD("MuxServer: UpStreamPayload: Parent line is not alive, stopping processing for cid: %u", frame.cid);
            lineUnlock(parent_l);
            return;
        }
        lineUnlock(parent_l);
    }

    // Only the incomplete remainder counts toward the limit. A single batch may legally carry far more than
    // kMaxMainChannelBufferSize bytes of complete frames, and those must be drained rather than judged an overflow.
    if (isOverFlow(&(parent_ls->read_stream)))
    {
        handleOverFlow(t, parent_l);
    }
}
