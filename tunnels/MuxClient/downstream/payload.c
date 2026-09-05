#include "structure.h"

#include "loggers/network_logger.h"

static bool handleCloseFrame(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                             muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    LOGD("MuxClient: DownStreamPayload: Close frame received, cid: %u", frame->cid);
    lineReuseBuffer(parent_l, frame_buffer);
    discard child_l;
    return muxclientBeginPeerCloseDrain(t, parent_l, ts, parent_ls, child_ls);
}

static bool processFrameForChild(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                                 muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    if (child_ls->close_state != kMuxClientChildCloseOpen)
    {
        lineReuseBuffer(parent_l, frame_buffer);
        return true;
    }

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
        if (! muxclientPauseChildSource(t, parent_l, child_ls, true, false))
        {
            return false;
        }
        break;

    case kMuxFlagFlowResume:
        // LOGD("MuxClient: DownStreamPayload: FlowResume frame received, cid: %u", frame->cid);
        lineReuseBuffer(parent_l, frame_buffer);
        if (! muxclientResumeChildSource(t, parent_l, child_ls, true, false))
        {
            return false;
        }
        break;

    case kMuxFlagData:
        // LOGD("MuxClient: DownStreamPayload: Data frame received, cid: %u", frame->cid);
        sbufShiftRight(frame_buffer, kMuxFrameLength);
        if (child_ls->paused)
        {
            return muxclientQueueChildPayload(t, parent_l, ts, parent_ls, child_ls, frame_buffer);
        }
        if (! lineCallWithRefWithBuf(child_l, tunnelPrevDownStreamPayload, t, frame_buffer))
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
        LOGW("MuxClient: DownStreamPayload: Read stream overflow, size: %zu, limit: %zu",
             bufferstreamGetBufLen(read_stream),
             kMaxMainChannelBufferSize);
        return true;
    }
    return false;
}

static void handleOverFlow(tunnel_t *t, line_t *parent_l)
{
    muxclientHandleParentLoss(t, parent_l, true);
}

void muxclientTunnelDownStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxclient_tstate_t *ts = tunnelGetState(t);
    // Do not decode a neighbour's final flush into new child or flow-control work.
    if (ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        lineReuseBuffer(parent_l, buf);
        return;
    }
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

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

        muxclient_lstate_t *child_ls = muxclientFindChildByConnectionId(parent_ls, frame.cid);
        if (! child_ls)
        {
            // LOGD("MuxClient: DownStreamPayload: No child line state found for cid: %u", frame.cid);
            lineReuseBuffer(parent_l, frame_buffer);
            continue;
        }

        lineRef(parent_l);
        if (! processFrameForChild(t, parent_l, &frame, frame_buffer, ts, parent_ls, child_ls))
        {
            lineUnref(parent_l);
            return;
        }

        if (! lineIsAlive(parent_l))
        {
            LOGD("MuxClient: DownStreamPayload: Parent line is not alive, stopping processing for cid: %u", frame.cid);
            lineUnref(parent_l);
            return;
        }
        lineUnref(parent_l);
    }

    // Only the incomplete remainder counts toward the limit. A single batch may legally carry far more than
    // kMaxMainChannelBufferSize bytes of complete frames, and those must be drained rather than judged an overflow.
    if (isOverFlow(&(parent_ls->read_stream)))
    {
        handleOverFlow(t, parent_l);
    }
}
