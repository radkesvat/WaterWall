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

static bool isOverFlow(splice_stream_t *read_stream)
{
    if (splicestreamLength(read_stream) > kMuxMaxBufferedFrameLength)
    {
        LOGW("MuxClient: DownStreamPayload: Read stream overflow, size: %zu, limit: %zu",
             splicestreamLength(read_stream),
             (size_t) kMuxMaxBufferedFrameLength);
        return true;
    }
    return false;
}

static void handleOverFlow(tunnel_t *t, line_t *parent_l)
{
    muxclientHandleParentLoss(t, parent_l, true);
}

static void processParentPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxclient_tstate_t *ts        = tunnelGetState(t);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    // Parent storage may coalesce; exact frame reads below restore the wire boundaries, including empty Data.
    if (! splicestreamPush(parent_ls->parent_state->read_stream, buf))
    {
        handleOverFlow(t, parent_l);
        return;
    }

    while (parent_ls->parent_state != NULL && ! parent_ls->parent_finishing &&
           ! ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        mux_frame_t frame = {0};
        const mux_peek_result_t result = muxPeekCompleteFrame(parent_ls->parent_state->read_stream, &frame);
        if (result == kMuxPeekInvalidLength)
        {
            LOGW("MuxClient: invalid frame payload length %u (maximum %u)",
                 (unsigned int) frame.length,
                 (unsigned int) kMuxMaxDataFrameLength);
            muxclientHandleParentLoss(t, parent_l, true);
            return;
        }
        if (result == kMuxPeekNeedMore)
        {
            break;
        }

        muxclient_lstate_t *child_ls = muxclientFindChildByConnectionId(parent_ls, frame.cid);
        const bool          retain   = frame.flags == kMuxFlagData && child_ls != NULL && child_ls->paused &&
                            child_ls->close_state == kMuxClientChildCloseOpen;
        const bool forward_splice = frame.flags == kMuxFlagData && child_ls != NULL && ! child_ls->paused &&
                                    child_ls->close_state == kMuxClientChildCloseOpen;
        sbuf_t *frame_buffer = muxReadFrameBody(parent_ls->parent_state->read_stream, &frame, retain || forward_splice);
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
    // kMuxMaxBufferedFrameLength bytes of complete frames, and those must be drained rather than judged an overflow.
    if (parent_ls->parent_state != NULL && isOverFlow(parent_ls->parent_state->read_stream))
    {
        handleOverFlow(t, parent_l);
        return;
    }
}

void muxclientTunnelDownStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxclient_tstate_t *ts     = tunnelGetState(t);
    muxclient_lstate_t *parent = lineGetState(parent_l, t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing)
    {
        lineReuseBuffer(parent_l, buf);
        return;
    }
    lineRef(parent_l);
    ++parent->parent_state->receive_depth;
    processParentPayload(t, parent_l, buf);
    if (lineIsAlive(parent_l) && parent->parent_state != NULL && ! parent->parent_finishing)
    {
        assert(parent->parent_state->receive_depth != 0);
        --parent->parent_state->receive_depth;
        if (! ts->worker_states[lineGetWID(parent_l)].quiescing)
            discard muxclientEnforceParentReceiveLimit(t, parent_l);
    }
    lineUnref(parent_l);
}
