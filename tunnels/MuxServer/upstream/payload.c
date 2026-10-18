#include "structure.h"

#include "loggers/network_logger.h"

static bool rejectFreshOpen(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, mux_cid_t cid,
                            const char *reason)
{
    muxserver_tstate_t *ts     = tunnelGetState(t);
    const uint64_t      now_ms = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(parent_l)));

    if (! muxserverConsumeRejectedOpenToken(parent_ls, now_ms))
    {
        if (atomicLogRateLimiterShouldLog(&ts->protocol_abuse_log_limiter, kMuxServerAdmissionLogIntervalMs))
        {
            LOGW("MuxServer: closing parent on worker %u after sustained rejected Opens (latest cid=%u)",
                 (unsigned int) lineGetWID(parent_l),
                 (unsigned int) cid);
        }
        muxserverHandleParentLoss(t, parent_l, true);
        return false;
    }

    if (atomicLogRateLimiterShouldLog(&ts->resource_admission_log_limiter, kMuxServerAdmissionLogIntervalMs))
    {
        LOGW("MuxServer: rejecting fresh Open cid %u on worker %u: %s (parent-live=%u aggregate-live=%u)",
             (unsigned int) cid,
             (unsigned int) lineGetWID(parent_l),
             reason,
             parent_ls->children_count,
             (unsigned int) atomicLoadRelaxed(&ts->live_children_count));
    }

    sbuf_t *close_frame = muxParentOutputControlBuffer(lineGetBufferPool(parent_l));
    muxMakeMuxFrame(close_frame, cid, kMuxFlagClose);
    return muxserverSendParentOutput(t, parent_l, close_frame, NULL, kMuxFlagClose);
}

static bool handleOpenFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, mux_frame_t *frame)
{
    LOGD("MuxServer: UpStreamPayload: Open frame received, cid: %u", frame->cid);

    muxserver_tstate_t *ts       = tunnelGetState(t);
    muxserver_lstate_t *existing = muxserverFindChildByConnectionId(parent_ls, frame->cid);
    if (existing != NULL)
    {
        if (atomicLogRateLimiterShouldLog(&ts->protocol_abuse_log_limiter, kMuxServerAdmissionLogIntervalMs))
        {
            LOGW("MuxServer: closing parent on duplicate Open cid %u", (unsigned int) frame->cid);
        }
        muxserverHandleParentLoss(t, parent_l, true);
        return false;
    }

    if (parent_ls->children_count >= ts->max_children)
    {
        return rejectFreshOpen(t, parent_l, parent_ls, frame->cid, "per-parent live-child limit reached");
    }

    const muxserver_memory_admission_t admission = muxserverEvaluateMemoryAdmission(ts);
    if (admission.gate_transitioned &&
        atomicLogRateLimiterShouldLog(&ts->memory_transition_log_limiter, kMuxServerAdmissionLogIntervalMs))
    {
        LOGW("MuxServer: memory admission gate %s at snapshot generation %llu (reserve=%u)",
             admission.gate_closed ? "closed" : "reopened",
             (unsigned long long) admission.snapshot_generation,
             ts->memory_reserve);
    }
    if (! admission.permits_memory)
    {
        return rejectFreshOpen(t, parent_l, parent_ls, frame->cid, "memory pressure gate is closed");
    }
    if (! muxserverTryReserveLiveChildSlot(ts, admission.effective_ceiling))
    {
        return rejectFreshOpen(t,
                               parent_l,
                               parent_ls,
                               frame->cid,
                               admission.snapshot_status == kSystemMemorySnapshotFresh
                                   ? "aggregate live-child limit reached"
                                   : "memory-snapshot fallback live-child limit reached");
    }

    line_t             *child_l      = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(parent_l));
    muxserver_lstate_t *new_child_ls = lineGetState(child_l, t);
    muxserverLinestateInitialize(t, new_child_ls, child_l, true, frame->cid);
    new_child_ls->child_slot_reserved = true;
    muxserverArmChildIdle(t, new_child_ls);
    muxserverJoinConnection(parent_ls, new_child_ls);

    lineRef(parent_l);
    new_child_ls->source_starting = true;
    lineRef(child_l);
    tunnelNextUpStreamInit(t, child_l);
    if (lineIsAlive(child_l) && ((muxserver_lstate_t *) lineGetState(child_l, t))->is_child)
        muxserverChildSourceStarted(t, child_l);
    lineUnref(child_l);
    bool    parent_alive = lineIsAlive(parent_l);
    lineUnref(parent_l);
    return parent_alive;
}

// Paused children retain Data, and later Data queues behind already retained bytes.
static bool childRetainsData(muxserver_lstate_t *child_ls)
{
    return child_ls->paused || bufferqueueGetBufCount(&child_ls->pending_child_data) != 0;
}

static bool processFrameForChild(tunnel_t *t, line_t *parent_l, mux_frame_t *frame, sbuf_t *frame_buffer,
                                 muxserver_tstate_t *ts, muxserver_lstate_t *parent_ls, muxserver_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    if (UNLIKELY(child_ls->close_state != kMuxServerChildCloseOpen))
    {
        if (frame_buffer != NULL)
            lineReuseBuffer(parent_l, frame_buffer);
        return true;
    }

    switch (frame->flags)
    {
    case kMuxFlagClose:
        LOGD("MuxServer: UpStreamPayload: Close frame received, cid: %u", frame->cid);
        if (! muxserverBeginPeerCloseDrain(t, parent_l, ts, parent_ls, child_ls))
        {
            return false;
        }
        break;

    case kMuxFlagFlowPause:
        // LOGD("MuxServer: UpStreamPayload: FlowPause frame received, cid: %u", frame->cid);
        if (! muxserverPauseChildSource(t, parent_l, child_ls, true, false))
        {
            return false;
        }
        break;

    case kMuxFlagFlowResume:
        // LOGD("MuxServer: UpStreamPayload: FlowResume frame received, cid: %u", frame->cid);
        if (! muxserverResumeChildSource(t, parent_l, child_ls, true, false))
        {
            return false;
        }
        break;

    case kMuxFlagData:
        // LOGD("MuxServer: UpStreamPayload: Data frame received, cid: %u", frame->cid);
        assert(frame_buffer != NULL && sbufGetLength(frame_buffer) != 0);
        if (child_ls->child_slot_reserved)
        {
            muxserverRefreshChildIdle(t, child_ls);
        }
        if (childRetainsData(child_ls))
        {
            lineRef(child_l);
            const bool parent_alive = muxserverQueueChildPayload(t, parent_l, ts, parent_ls, child_ls, frame_buffer);
            if (parent_alive && lineIsAlive(child_l) && child_ls->is_child && child_ls->parent == parent_ls &&
                child_ls->close_state == kMuxServerChildCloseOpen && ! child_ls->paused)
                discard muxserverDrainAttachedChild(t, parent_l, parent_ls, child_l, child_ls);
            lineUnref(child_l);
            return lineIsAlive(parent_l);
        }
        if (! lineCallWithRefWithBuf(child_l, tunnelNextUpStreamPayload, t, frame_buffer))
        {
            return lineIsAlive(parent_l);
        }
        break;

    default:
        // LOGD("MuxServer: UpStreamPayload: Unknown frame type received, cid: %u", frame->cid);
        break;
    }
    return true;
}

static bool isOverFlow(splice_stream_t *read_stream)
{
    if (splicestreamLength(read_stream) > kMuxMaxBufferedFrameLength)
    {
        LOGW("MuxServer: UpStreamPayload: Read stream overflow, size: %zu, limit: %zu",
             splicestreamLength(read_stream),
             (size_t) kMuxMaxBufferedFrameLength);
        return true;
    }
    return false;
}

static void handleOverFlow(tunnel_t *t, line_t *parent_l)
{
    muxserverHandleParentLoss(t, parent_l, true);
}

static void processParentPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxserver_tstate_t *ts        = tunnelGetState(t);
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

    // Append before callbacks so nested input follows every older carrier byte.
    if (buf != NULL && UNLIKELY(! splicestreamPush(parent_ls->parent_state->read_stream, buf)))
    {
        handleOverFlow(t, parent_l);
        return;
    }

    while (lineIsAlive(parent_l) && parent_ls->parent_state != NULL && ! parent_ls->parent_finishing &&
           ! ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        muxserver_parent_state_t *state  = parent_ls->parent_state;
        splice_stream_t          *stream = state->read_stream;
        if (! state->reading_frame)
        {
            const mux_peek_result_t result = muxPeekFrameHeader(stream, &state->read_frame);
            if (UNLIKELY(result == kMuxPeekInvalidLength))
            {
                LOGW("MuxServer: invalid frame payload length %u (maximum %u)",
                     (unsigned int) state->read_frame.length,
                     (unsigned int) kMuxMaxDataFrameLength);
                muxserverHandleParentLoss(t, parent_l, true);
                return;
            }
            if (result == kMuxPeekNeedMore)
                break;
            state->reading_frame  = true;
            state->read_remaining = state->read_frame.length;
            state->discard_frame  = false;
        }

        mux_frame_t         frame    = state->read_frame;
        muxserver_lstate_t *child_ls = muxserverFindChildByConnectionId(parent_ls, frame.cid);
        if (frame.flags == kMuxFlagData && (child_ls == NULL || child_ls->close_state != kMuxServerChildCloseOpen))
            state->discard_frame = true;
        const uint32_t count = (uint32_t) min(splicestreamBodyBytes(stream), (size_t) state->read_remaining);
        if (count == 0 && state->read_remaining != 0)
            break;
        const bool finished = count == state->read_remaining;
        const bool deliver  = frame.flags == kMuxFlagData && ! state->discard_frame && count != 0;
        // A retaining child takes the rest of this frame as one queue entry once it has arrived.
        if (deliver && ! finished && childRetainsData(child_ls))
        {
            // Kept bytes still count as child activity.
            if (child_ls->child_slot_reserved)
                muxserverRefreshChildIdle(t, child_ls);
            break;
        }

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
            if (! ts->keepalive || frame.flags == kMuxFlagPong)
                continue;
            if (frame.length != 0)
            {
                LOGW("MuxServer: keepalive Ping must have an empty body");
                muxserverHandleParentLoss(t, parent_l, true);
                return;
            }
            sbuf_t *control = muxParentOutputControlBuffer(lineGetBufferPool(parent_l));
            muxMakeMuxFrame(control, frame.cid, kMuxFlagPong);
            if (! muxserverSendParentOutput(t, parent_l, control, NULL, kMuxFlagPong))
                return;
            continue;
        }

        if (frame.flags == kMuxFlagOpen)
        {
            if (! handleOpenFrame(t, parent_l, parent_ls, &frame))
                return;
            continue;
        }

        if (child_ls != NULL && ! processFrameForChild(t, parent_l, &frame, NULL, ts, parent_ls, child_ls))
            return;
    }

    // Ready DATA chunks drain before checking the retained carrier suffix.
    if (lineIsAlive(parent_l) && parent_ls->parent_state != NULL && isOverFlow(parent_ls->parent_state->read_stream))
        handleOverFlow(t, parent_l);
}

// NULL input parses only bytes already in the stream.
static void receiveParentInput(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxserver_tstate_t *ts     = tunnelGetState(t);
    muxserver_lstate_t *parent = lineGetState(parent_l, t);
    assert(! ts->worker_states[lineGetWID(parent_l)].quiescing && ! parent->parent_finishing);
    lineRef(parent_l);
    ++parent->parent_state->receive_depth;
    processParentPayload(t, parent_l, buf);
    if (lineIsAlive(parent_l) && parent->parent_state != NULL && ! parent->parent_finishing)
    {
        assert(parent->parent_state->receive_depth != 0);
        --parent->parent_state->receive_depth;
        if (! ts->worker_states[lineGetWID(parent_l)].quiescing)
            discard muxserverEnforceParentReceiveLimit(t, parent_l);
    }
    lineUnref(parent_l);
}

void muxserverTunnelUpStreamPayload(tunnel_t *t, line_t *parent_l, sbuf_t *buf)
{
    muxserver_tstate_t *ts     = tunnelGetState(t);
    muxserver_lstate_t *parent = lineGetState(parent_l, t);
    if (UNLIKELY(ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing))
    {
        lineReuseBuffer(parent_l, buf);
        return;
    }
    receiveParentInput(t, parent_l, buf);
}

void muxserverDeliverKeptChildData(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *child_ls)
{
    muxserver_tstate_t *ts     = tunnelGetState(t);
    muxserver_lstate_t *parent = lineGetState(parent_l, t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing)
        return;
    /* An active receive loop rereads the published frame after every callback and
     * delivers kept bytes itself, so a Resume nested in parent input leaves them to it. */
    const muxserver_parent_state_t *state = parent->parent_state;
    if (state->receive_depth == 0 && state->reading_frame && state->read_frame.flags == kMuxFlagData &&
        state->read_frame.cid == child_ls->connection_id && splicestreamBodyBytes(state->read_stream) != 0)
        receiveParentInput(t, parent_l, NULL);
}
