#include "structure.h"

#include "loggers/network_logger.h"

static bool rejectFreshOpen(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, mux_cid_t cid,
                            const char *reason)
{
    muxserver_tstate_t *ts     = tunnelGetState(t);
    const uint64_t      now_ms = wloopNowMS(getWorkerLoop(lineGetWID(parent_l)));

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

    sbuf_t *close_frame = bufferpoolGetSmallBuffer(lineGetBufferPool(parent_l));
    muxMakeMuxFrame(close_frame, cid, kMuxFlagClose);
    lineRef(parent_l);
    tunnelPrevDownStreamPayload(t, parent_l, close_frame);
    const bool parent_alive = lineIsAlive(parent_l);
    lineUnref(parent_l);
    return parent_alive;
}

static bool handleOpenFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, mux_frame_t *frame,
                            sbuf_t *frame_buffer)
{
    lineReuseBuffer(parent_l, frame_buffer);
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
    discard lineCallWithRef(child_l, tunnelNextUpStreamInit, t);
    bool    parent_alive = lineIsAlive(parent_l);
    lineUnref(parent_l);
    return parent_alive;
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
        if (sbufGetLength(frame_buffer) != 0 && child_ls->child_slot_reserved)
        {
            muxserverRefreshChildIdle(t, child_ls);
        }
        if (child_ls->paused)
        {
            return muxserverQueueChildPayload(t, parent_l, ts, parent_ls, child_ls, frame_buffer);
        }
        if (! lineCallWithRefWithBuf(child_l, tunnelNextUpStreamPayload, t, frame_buffer))
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
    muxserver_tstate_t *ts = tunnelGetState(t);
    // A borrowed parent can flush after worker stop; never reopen the drained child inventory.
    if (ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        lineReuseBuffer(parent_l, buf);
        return;
    }
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

        muxserver_lstate_t *child_ls = muxserverFindChildByConnectionId(parent_ls, frame.cid);
        if (! child_ls)
        {
            // LOGD("MuxServer: UpStreamPayload: No child line state found for cid: %u", frame.cid);
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
            LOGD("MuxServer: UpStreamPayload: Parent line is not alive, stopping processing for cid: %u", frame.cid);
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
