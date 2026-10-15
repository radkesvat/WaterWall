#include "structure.h"

#include "loggers/network_logger.h"

static bool handleCloseFrame(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, muxclient_tstate_t *ts,
                             muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    LOGD("MuxClient: DownStreamPayload: Close frame received, cid: %u", frame->cid);
    return muxclientBeginPeerCloseDrain(t, parent_l, ts, parent_ls, child_ls);
}

static bool processFrameForChild(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                                 muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    if (UNLIKELY(child_ls->close_state != kMuxClientChildCloseOpen))
    {
        if (frame_buffer != NULL)
            lineReuseBuffer(parent_l, frame_buffer);
        return true;
    }

    switch (frame->flags)
    {
    case kMuxFlagOpen:
        LOGE("MuxClient: DownStreamPayload: Open frame received, cid: %u, but no Open flag should be sent to "
             "MuxClient node",
             frame->cid);
        break;

    case kMuxFlagClose:
        if (! handleCloseFrame(t, parent_l, frame, ts, parent_ls, child_ls))
        {
            return false;
        }
        break;

    case kMuxFlagFlowPause:
        // LOGD("MuxClient: DownStreamPayload: FlowPause frame received, cid: %u", frame->cid);
        if (! muxclientPauseChildSource(t, parent_l, child_ls, true, false))
        {
            return false;
        }
        break;

    case kMuxFlagFlowResume:
        // LOGD("MuxClient: DownStreamPayload: FlowResume frame received, cid: %u", frame->cid);
        if (! muxclientResumeChildSource(t, parent_l, child_ls, true, false))
        {
            return false;
        }
        break;

    case kMuxFlagData:
        // LOGD("MuxClient: DownStreamPayload: Data frame received, cid: %u", frame->cid);
        if (child_ls->paused || bufferqueueGetBufCount(&child_ls->pending_child_data) != 0)
        {
            lineRef(child_l);
            const bool parent_alive = muxclientQueueChildPayload(t, parent_l, ts, parent_ls, child_ls, frame_buffer);
            if (parent_alive && lineIsAlive(child_l) && child_ls->is_child && child_ls->parent == parent_ls &&
                child_ls->close_state == kMuxClientChildCloseOpen && ! child_ls->paused)
                discard muxclientDrainAttachedChild(t, parent_l, parent_ls, child_l, child_ls);
            lineUnref(child_l);
            return lineIsAlive(parent_l);
        }
        if (! lineCallWithRefWithBuf(child_l, tunnelPrevDownStreamPayload, t, frame_buffer))
        {
            return lineIsAlive(parent_l);
        }
        break;

    default:
        LOGD("MuxClient: DownStreamPayload: Unknown frame type received, cid: %u", frame->cid);
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

    // Append before callbacks so nested input follows every older carrier byte.
    if (UNLIKELY(! splicestreamPush(parent_ls->parent_state->read_stream, buf)))
    {
        handleOverFlow(t, parent_l);
        return;
    }

    while (lineIsAlive(parent_l) && parent_ls->parent_state != NULL && ! parent_ls->parent_finishing &&
           ! ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        muxclient_parent_state_t *state  = parent_ls->parent_state;
        splice_stream_t          *stream = state->read_stream;
        if (! state->reading_frame)
        {
            const mux_peek_result_t result = muxPeekFrameHeader(stream, &state->read_frame);
            if (UNLIKELY(result == kMuxPeekInvalidLength))
            {
                LOGW("MuxClient: invalid frame payload length %u (maximum %u)",
                     (unsigned int) state->read_frame.length,
                     (unsigned int) kMuxMaxDataFrameLength);
                muxclientHandleParentLoss(t, parent_l, true);
                return;
            }
            if (result == kMuxPeekNeedMore)
                break;
            state->reading_frame  = true;
            state->read_remaining = state->read_frame.length;
            state->discard_frame  = false;
        }

        mux_frame_t         frame    = state->read_frame;
        muxclient_lstate_t *child_ls = muxclientFindChildByConnectionId(parent_ls, frame.cid);
        if (frame.flags == kMuxFlagData && (child_ls == NULL || child_ls->close_state != kMuxClientChildCloseOpen))
            state->discard_frame = true;
        const uint32_t count = (uint32_t) min(splicestreamBodyBytes(stream), (size_t) state->read_remaining);
        if (count == 0 && state->read_remaining != 0)
            break;
        const bool finished = count == state->read_remaining;
        const bool deliver  = frame.flags == kMuxFlagData && ! state->discard_frame && count != 0;

        // Publish all progress before delivery: nested input may complete this
        // frame, process siblings, or destroy either exact line.
        state->read_remaining -= count;
        state->reading_frame = ! finished;
        if (deliver)
        {
            sbuf_t *body = splicestreamMoveFrameChunk(
                stream, bufferpoolGetSpliceBuffer(lineGetBufferPool(parent_l)), count, finished);
            if (! processFrameForChild(t, parent_l, &frame, body, ts, parent_ls, child_ls))
                return;
            continue;
        }

        // Missing/closed children and empty DATA produce no child callback.
        // Controls are applied only at the end of their declared body.
        splicestreamDiscardFrameChunk(stream, count, finished);
        if (! finished || frame.flags == kMuxFlagData)
            continue;
        if (frame.flags == kMuxFlagPing || frame.flags == kMuxFlagPong)
        {
            if (ts->keepalive && frame.length != 0)
            {
                LOGW("MuxClient: keepalive control must have an empty body");
                muxclientHandleParentLoss(t, parent_l, true);
                return;
            }
            if (ts->keepalive && frame.flags == kMuxFlagPong && state->awaiting_pong && frame.cid == state->ping_token)
            {
                state->peer_keepalive = true;
                muxclientAcknowledgePong(state);
            }
            continue;
        }

        if (child_ls != NULL && ! processFrameForChild(t, parent_l, &frame, NULL, ts, parent_ls, child_ls))
            return;
    }

    // Ready DATA chunks drain before checking the retained carrier suffix.
    if (lineIsAlive(parent_l) && parent_ls->parent_state != NULL && isOverFlow(parent_ls->parent_state->read_stream))
        handleOverFlow(t, parent_l);
}

void muxclientTunnelDownStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxclient_tstate_t *ts     = tunnelGetState(t);
    muxclient_lstate_t *parent = lineGetState(parent_l, t);
    if (UNLIKELY(ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing))
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
