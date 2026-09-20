#include "structure.h"

#include "loggers/network_logger.h"

void muxclientJoinConnection(muxclient_lstate_t *parent, muxclient_lstate_t *child)
{
    assert(child != NULL && parent != NULL && child->is_child && (parent->is_child == false));
    if (UNLIKELY(parent->parent_state == NULL || parent->children_count == UINT32_MAX ||
                 muxclientFindChildByConnectionId(parent, child->connection_id) != NULL))
    {
        LOGF("MuxClient: duplicate CID insertion or parent child-count overflow");
        abortProgramNow(1);
    }
    if (UNLIKELY(
            ! muxclient_child_map_t_insert(&parent->parent_state->child_map, child->connection_id, child).inserted))
    {
        LOGF("MuxClient: failed to publish child CID index entry");
        abortProgramNow(1);
    }
    child->parent = parent;

    child->child_next = parent->child_next;
    child->child_prev = NULL;

    if (parent->child_next != NULL)
    {
        parent->child_next->child_prev = child;
    }

    parent->child_next = child;
    if (parent->parent_state->resume_cursor == NULL)
        parent->parent_state->resume_cursor = child;

    parent->children_count++;
}

void muxclientLeaveConnection(muxclient_lstate_t *child)
{
    if (UNLIKELY(child == NULL || ! child->is_child || child->parent == NULL))
    {
        LOGF("MuxClient: attempted to unlink a child without a live parent link");
        abortProgramNow(1);
    }

    muxclient_lstate_t        *parent = child->parent;
    muxclient_child_map_t_iter indexed =
        muxclient_child_map_t_find(&parent->parent_state->child_map, child->connection_id);
    if (UNLIKELY(indexed.ref == muxclient_child_map_t_end(&parent->parent_state->child_map).ref ||
                 indexed.ref->second != child))
    {
        LOGF("MuxClient: child CID index disagrees with ownership list");
        abortProgramNow(1);
    }
    muxclient_child_map_t_erase_at(&parent->parent_state->child_map, indexed);

    if (child->child_prev != NULL)
    {
        child->child_prev->child_next = child->child_next;
    }
    else
    {
        child->parent->child_next = child->child_next;
    }

    if (child->child_next != NULL)
    {
        child->child_next->child_prev = child->child_prev;
    }

    if (UNLIKELY(child->parent->children_count == 0))
    {
        LOGF("MuxClient: parent child-count underflow");
        abortProgramNow(1);
    }
    child->parent->children_count--;
    if (parent->parent_state->resume_cursor == child)
        parent->parent_state->resume_cursor = child->child_next ? child->child_next : parent->child_next;

    child->parent     = NULL;
    child->child_prev = NULL;
    child->child_next = NULL;
}

muxclient_lstate_t *muxclientFindChildByConnectionId(muxclient_lstate_t *parent, mux_cid_t cid)
{
    assert(parent != NULL && ! parent->is_child && parent->parent_state != NULL);
    muxclient_child_map_t_iter found = muxclient_child_map_t_find(&parent->parent_state->child_map, cid);
    return found.ref == muxclient_child_map_t_end(&parent->parent_state->child_map).ref ? NULL : found.ref->second;
}

bool muxclientCheckConnectionIsExhausted(muxclient_tstate_t *ts, muxclient_lstate_t *ls)
{
    assert(ls->is_child == false);

    if (ls->connection_id == kMuxCidMax)
    {
        LOGE("MuxClient: Connection exhausted, connection id reached maximum value: %u", kMuxCidMax);
        return true;
    }

    if (ls->children_count == kMuxCidMax)
    {
        LOGE("MuxClient: Connection exhausted, children count reached maximum value: %u", kMuxCidMax);
        return true; // Connection is exhausted
    }

    if (ts->max_children != 0 && ls->children_count >= ts->max_children)
    {
        return true;
    }

    if (ts->concurrency_mode == kConcurrencyModeTimer)
    {
        if (wloopNowMS(getWorkerLoop(lineGetWID(ls->l))) < ts->concurrency_duration + ls->creation_epoch)
        {
            return false; // Connection is not exhausted yet
        }
        return true;
    }

    if (ts->concurrency_mode == kConcurrencyModeCounter)
    {
        if (ls->connection_id < ts->concurrency_capacity)
        {
            return false; // Connection is not exhausted yet
        }
        return true;
    }

    if (ts->concurrency_mode == kConcurrencyModeFixedConnectionsCount)
    {
        return false;
    }

    assert(false);
    return true;
}

static bool muxclientParentShouldCloseWhenIdle(muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls)
{
    return parent_ls->selection_retired || muxclientCheckConnectionIsExhausted(ts, parent_ls);
}

static line_t **muxclientFixedParentSlot(muxclient_tstate_t *ts, wid_t wid, uint32_t index)
{
    return &ts->fixed_parent_lines[((size_t) wid * (size_t) ts->fixed_connections_count) + (size_t) index];
}

void muxclientForgetParentSelection(muxclient_tstate_t *ts, wid_t wid, line_t *parent_l)
{
    if (ts->concurrency_mode == kConcurrencyModeFixedConnectionsCount)
    {
        for (uint32_t i = 0; i < ts->fixed_connections_count; ++i)
        {
            line_t **slot = muxclientFixedParentSlot(ts, wid, i);
            if (*slot == parent_l)
            {
                *slot = NULL;
                return;
            }
        }
        return;
    }

    if (ts->unsatisfied_lines[wid] == parent_l)
    {
        ts->unsatisfied_lines[wid] = NULL;
    }
}

typedef struct muxclient_parent_stats_s
{
    uint32_t parent_write_paused;
    uint32_t peer_flow_paused;
    uint32_t child_read_paused;
    uint32_t child_write_paused;
    uint32_t children_close_pending;
} muxclient_parent_stats_t;

static void muxclientCollectParentStats(muxclient_lstate_t *parent_ls, muxclient_parent_stats_t *stats)
{
    memoryZero(stats, sizeof(*stats));

    for (muxclient_lstate_t *child_ls = parent_ls->child_next; child_ls != NULL; child_ls = child_ls->child_next)
    {
        if (child_ls->peer_flow_paused || child_ls->parent_write_paused)
        {
            stats->child_read_paused++;
        }
        if (child_ls->parent_write_paused)
        {
            stats->parent_write_paused++;
        }
        if (child_ls->peer_flow_paused)
            stats->peer_flow_paused++;
        if (child_ls->paused)
        {
            stats->child_write_paused++;
        }
        if (child_ls->close_state == kMuxClientChildClosePeerDraining)
        {
            stats->children_close_pending++;
        }
    }
}

static void muxclientParentStatsLogTask(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t *ts        = tunnelGetState(t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        return;
    }

    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    if (! ts->log_main_line_stats || parent_ls->is_child)
    {
        return;
    }

    muxclient_parent_stats_t stats;
    muxclientCollectParentStats(parent_ls, &stats);

    mux_parent_output_t *output = &parent_ls->parent_state->output;
    const uint64_t       now_us = wloopNowLoopRunTime(getWorkerLoop(lineGetWID(parent_l)));
    LOGI("MuxClient: main line stats wid=%u children-count=%u children-close-pending=%u "
         "childs-read-paused=%u childs-write-paused=%u "
         "parent-child-queue-charge=%zu parent-input-queue-charge=%zu "
         "parent-output-queued-bytes=%zu parent-output-queue-charge=%zu parent-output-queue-items=%zu "
         "parent-transport-paused=%s parent-sources-throttled=%s "
         "children-parent-write-paused=%u children-peer-flow-paused=%u "
         "parent-output-throttle-ms=%llu parent-output-last-throttle-ms=%llu "
         "parent-write-buffer-pause-threshold=%u parent-write-buffer-resume-threshold=%u parent-write-buffer-limit=%u",
         (unsigned int) lineGetWID(parent_l),
         parent_ls->children_count,
         stats.children_close_pending,
         stats.child_read_paused,
         stats.child_write_paused,
         parent_ls->pending_child_queue_charge,
         splicestreamCharge(parent_ls->parent_state->read_stream),
         (size_t) bufferqueueGetBufLen(&output->pending),
         output->charge,
         (size_t) bufferqueueGetBufCount(&output->pending),
         boolToYesNo(output->transport_paused),
         boolToYesNo(output->sources_throttled),
         stats.parent_write_paused,
         stats.peer_flow_paused,
         (unsigned long long) muxParentOutputThrottleMS(output, now_us),
         (unsigned long long) (output->last_throttle_us / 1000),
         ts->parent_write_pause_threshold,
         ts->parent_write_resume_threshold,
         ts->parent_write_limit);

    if (! parent_ls->parent_finishing)
    {
        /* Optional statistics sampling is intentionally lossy under pressure. */
        const line_task_submit_result_e result =
            lineScheduleDelayedTask(parent_l, muxclientParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t, NULL);
        discard result;
    }
}

void muxclientScheduleParentStatsLog(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        return;
    }

    if (! ts->log_main_line_stats)
    {
        return;
    }

    /* Optional statistics sampling is intentionally lossy under pressure. */
    const line_task_submit_result_e result =
        lineScheduleDelayedTask(parent_l, muxclientParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t, NULL);
    discard result;
}

void muxclientRegisterParent(muxclient_tstate_t *ts, muxclient_lstate_t *ls)
{
    muxclient_worker_state_t *worker = &ts->worker_states[lineGetWID(ls->l)];
    muxclient_parent_state_t *state  = ls->parent_state;
    assert(! state->owned);
    state->owner_next = worker->owned_parents;
    if (state->owner_next != NULL)
    {
        state->owner_next->parent_state->owner_prev = ls;
    }
    worker->owned_parents = ls;
    state->owned          = true;
}

void muxclientUnregisterParent(muxclient_tstate_t *ts, muxclient_lstate_t *ls)
{
    muxclient_worker_state_t *worker = &ts->worker_states[lineGetWID(ls->l)];
    muxclient_parent_state_t *state  = ls->parent_state;
    assert(state->owned);
    if (state->owner_prev != NULL)
    {
        state->owner_prev->parent_state->owner_next = state->owner_next;
    }
    else
    {
        assert(worker->owned_parents == ls);
        worker->owned_parents = state->owner_next;
    }
    if (state->owner_next != NULL)
    {
        state->owner_next->parent_state->owner_prev = state->owner_prev;
    }
    state->owner_prev = NULL;
    state->owner_next = NULL;
    state->owned      = false;
}

static bool muxclientCreateParentLine(tunnel_t *t, wid_t wid, line_t **selection_slot)
{
    line_t             *parent_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    muxclientLinestateInitialize(t, parent_ls, parent_l, false, 0);
    muxclientRegisterParent(tunnelGetState(t), parent_ls);
    assert(*selection_slot == NULL);
    *selection_slot = parent_l;

    if (! lineCallWithRef(parent_l, tunnelNextUpStreamInit, t))
    {
        return false;
    }

    muxclientScheduleParentStatsLog(t, parent_l);
    return true;
}

void muxclientCloseIdleExhaustedParentLine(tunnel_t *t, muxclient_tstate_t *ts, wid_t wid, line_t *parent_l,
                                           muxclient_lstate_t *parent_ls)
{
    assert(parent_ls->is_child == false);
    assert(parent_ls->children_count == 0);

    muxclientForgetParentSelection(ts, wid, parent_l);
    parent_ls->selection_retired = true;
    mux_parent_output_t *output  = &parent_ls->parent_state->output;
    if (output->pumping || output->notifying || bufferqueueGetBufCount(&output->pending) != 0)
    {
        return;
    }
    lineRef(parent_l);
    muxclientUnregisterParent(ts, parent_ls);
    muxclientLinestateDestroy(parent_ls);
    tunnelNextUpStreamFinish(t, parent_l);

    if (lineIsAlive(parent_l))
    {
        lineDestroy(parent_l);
    }
    lineUnref(parent_l);
}

static line_t *muxclientGetFixedParentLineForNewChild(tunnel_t *t, muxclient_tstate_t *ts, wid_t wid)
{
    assert(ts->fixed_connections_count > 0);

    for (uint32_t i = 0; i < ts->fixed_connections_count; ++i)
    {
        line_t **slot = muxclientFixedParentSlot(ts, wid, i);
        if (*slot != NULL)
        {
            continue;
        }

        if (! muxclientCreateParentLine(t, wid, slot))
        {
            return NULL;
        }
    }

    uint32_t start_index = ts->fixed_next_parent_indexes[wid] % ts->fixed_connections_count;
    uint32_t best_index  = start_index;
    uint32_t best_count  = UINT32_MAX;
    bool     found       = false;

    for (uint32_t i = 0; i < ts->fixed_connections_count; ++i)
    {
        uint32_t idx      = (start_index + i) % ts->fixed_connections_count;
        line_t  *parent_l = *muxclientFixedParentSlot(ts, wid, idx);
        assert(parent_l != NULL);

        muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);
        assert(parent_ls->is_child == false);

        if (parent_ls->parent_finishing || muxclientCheckConnectionIsExhausted(ts, parent_ls))
        {
            continue;
        }

        if (! found || parent_ls->children_count < best_count)
        {
            best_index = idx;
            best_count = parent_ls->children_count;
            found      = true;
        }
    }

    if (! found)
    {
        return NULL;
    }

    ts->fixed_next_parent_indexes[wid] = (best_index + 1U) % ts->fixed_connections_count;
    return *muxclientFixedParentSlot(ts, wid, best_index);
}

line_t *muxclientGetParentLineForNewChild(tunnel_t *t, line_t *child_l)
{
    muxclient_tstate_t *ts  = tunnelGetState(t);
    wid_t               wid = lineGetWID(child_l);

    if (ts->concurrency_mode == kConcurrencyModeFixedConnectionsCount)
    {
        return muxclientGetFixedParentLineForNewChild(t, ts, wid);
    }

    line_t *candidate_parent_l = ts->unsatisfied_lines[wid];
    if (candidate_parent_l != NULL)
    {
        muxclient_lstate_t *candidate_parent_ls = lineGetState(candidate_parent_l, t);
        if (muxclientCheckConnectionIsExhausted(ts, candidate_parent_ls))
        {
            if (candidate_parent_ls->children_count == 0)
            {
                muxclientCloseIdleExhaustedParentLine(t, ts, wid, candidate_parent_l, candidate_parent_ls);
            }
            else
            {
                candidate_parent_ls->selection_retired = true;
                ts->unsatisfied_lines[wid]             = NULL;
            }
        }
    }

    if (ts->unsatisfied_lines[wid] == NULL)
    {
        if (! muxclientCreateParentLine(t, wid, &ts->unsatisfied_lines[wid]))
        {
            return NULL;
        }
    }

    return ts->unsatisfied_lines[wid];
}

static void muxclientCloseChildKeepParentImpl(tunnel_t *t, muxclient_tstate_t *ts, line_t *parent_l,
                                              muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls,
                                              bool notify_child_prev)
{
    if (ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        line_t *child_l = child_ls->l;
        muxclientLeaveConnection(child_ls);
        discard muxclientReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);
        muxclientLinestateDestroy(child_ls);
        if (notify_child_prev)
        {
            tunnelPrevDownStreamFinish(t, child_l);
        }
        return;
    }

    line_t         *child_l     = child_ls->l;
    const mux_cid_t cid         = child_ls->connection_id;
    const bool      open_submitted = child_ls->open_frame_submitted;
    const bool      notify_peer = child_ls->close_state == kMuxClientChildCloseOpen;

    muxclientLeaveConnection(child_ls);

    const bool parent_alive = muxclientReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);

    if (! parent_alive || parent_ls->parent_finishing || ! notify_peer)
    {
        // A dying parent needs no child Close, and a peer-close drain must not echo a duplicate Close.
        muxclientLinestateDestroy(child_ls);
        if (notify_child_prev)
        {
            tunnelPrevDownStreamFinish(t, child_l);
        }
        if (parent_alive && lineIsAlive(parent_l) && parent_ls->parent_state != NULL && ! parent_ls->parent_finishing &&
            muxclientParentShouldCloseWhenIdle(ts, parent_ls) && parent_ls->children_count == 0)
        {
            muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent_ls);
        }
        return;
    }

    buffer_pool_t *pool             = lineGetBufferPool(parent_l);
    sbuf_t        *finishpacket_buf = muxParentOutputControlBuffer(pool);
    if (open_submitted)
    {
        muxMakeMuxFrame(finishpacket_buf, cid, kMuxFlagClose);
    }
    else
    {
        muxMakeMuxOpenCloseFrames(finishpacket_buf, cid);
    }

    muxclientLinestateDestroy(child_ls);

    if (notify_child_prev)
    {
        // the previous adapter owns the child line and destroys it, we only notify it
        tunnelPrevDownStreamFinish(t, child_l);
    }

    if (! lineIsAlive(parent_l) || parent_ls->parent_state == NULL || parent_ls->parent_finishing)
    {
        bufferpoolReuseBuffer(pool, finishpacket_buf);
        return;
    }

    if (! muxclientSendParentOutput(t, parent_l, finishpacket_buf, NULL, kMuxFlagClose))
    {
        return;
    }

    if (muxclientParentShouldCloseWhenIdle(ts, parent_ls) && parent_ls->children_count == 0)
    {
        muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent_ls);
    }
}

void muxclientCloseChildKeepParent(tunnel_t *t, muxclient_tstate_t *ts, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                   muxclient_lstate_t *child_ls, bool notify_child_prev)
{
    lineRef(parent_l);
    muxclientCloseChildKeepParentImpl(t, ts, parent_l, parent_ls, child_ls, notify_child_prev);
    lineUnref(parent_l);
}

static void muxclientAddChildQueueCharge(muxclient_lstate_t *child_ls, size_t charge)
{
    assert(child_ls != NULL && child_ls->is_child);
    if (UNLIKELY(child_ls->pending_child_queue_charge > SIZE_MAX - charge))
    {
        LOGF("MuxClient: child retained queue-charge accounting overflow");
        abortProgramNow(1);
    }

    child_ls->pending_child_queue_charge += charge;
}

static void muxclientSubtractChildQueueCharge(muxclient_lstate_t *child_ls, size_t charge)
{
    assert(child_ls != NULL && child_ls->is_child);
    if (UNLIKELY(child_ls->pending_child_queue_charge < charge))
    {
        LOGF("MuxClient: child retained queue-charge accounting underflow");
        abortProgramNow(1);
    }

    child_ls->pending_child_queue_charge -= charge;
}

static void muxclientAddParentPendingChildCharge(muxclient_lstate_t *parent_ls, size_t charge)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    if (UNLIKELY(parent_ls->pending_child_queue_charge > SIZE_MAX - charge))
    {
        LOGF("MuxClient: parent retained child-queue charge accounting overflow");
        abortProgramNow(1);
    }

    parent_ls->pending_child_queue_charge += charge;
}

static void muxclientSubtractParentPendingChildCharge(muxclient_lstate_t *parent_ls, size_t charge)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    if (UNLIKELY(parent_ls->pending_child_queue_charge < charge))
    {
        LOGF("MuxClient: parent retained child-queue charge accounting underflow");
        abortProgramNow(1);
    }

    parent_ls->pending_child_queue_charge -= charge;
}

static void muxclientReleaseChildPendingCharge(tunnel_t *t, muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    discard      t;
    const size_t pending_charge = child_ls->pending_child_queue_charge;
    const size_t pending_count  = bufferqueueGetBufCount(&child_ls->pending_child_data);
    if (UNLIKELY((pending_charge == 0) != (pending_count == 0)))
    {
        LOGF("MuxClient: attached child queue count/charge invariant failed during release");
        abortProgramNow(1);
    }
    if (pending_charge == 0)
    {
        return;
    }

    muxclientSubtractParentPendingChildCharge(parent_ls, pending_charge);
    child_ls->pending_child_queue_charge = 0;
    const size_t discarded = muxDiscardRetainedQueue(&child_ls->pending_child_data, lineGetBufferPool(child_ls->l));
    if (UNLIKELY(discarded != pending_charge))
    {
        LOGF("Mux: attached child resource charge disagrees with queued ownership");
        abortProgramNow(1);
    }
}

bool muxclientSendControlFrame(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                               mux_cid_t cid, uint8_t flag)
{
    if (parent_ls->parent_finishing)
        return false;
    muxclient_lstate_t *child       = lineGetState(child_l, t);
    buffer_pool_t      *pool        = lineGetBufferPool(parent_l);
    sbuf_t             *control_buf = muxParentOutputControlBuffer(pool);
    muxMakeMuxFrame(control_buf, cid, flag);
    lineRef(child_l);
    const bool parent_alive = muxclientSendParentOutput(t, parent_l, control_buf, child, flag);
    const bool child_alive = lineIsAlive(child_l);
    lineUnref(child_l);
    return parent_alive && child_alive;
}

bool muxclientSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                                 muxclient_lstate_t *child_ls)
{
    if (parent_ls->parent_finishing || child_ls->close_state != kMuxClientChildCloseOpen || child_ls->flow_paused_sent)
    {
        return true;
    }

    return muxclientSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowPause);
}

/*
 * Queue pressure must not pause reads on the shared parent transport. Such a pause
 * blocks every child on the parent until the particular local child that caused it
 * starts draining again. Per-child FlowPause/FlowResume already asks the peer to stop
 * producing for that cid; the aggregate memory bound below protects the process
 * without turning one indefinitely blocked destination into a parent-wide stall.
 */
bool muxclientReleaseParentInputForChildClose(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                              muxclient_lstate_t *child_ls)
{
    muxclientReleaseChildPendingCharge(t, parent_ls, child_ls);
    return lineIsAlive(parent_l);
}

static bool muxclientChildSourcePaused(muxclient_lstate_t *child_ls)
{
    return child_ls->peer_flow_paused || child_ls->parent_write_paused ||
           child_ls->close_state != kMuxClientChildCloseOpen;
}

bool muxclientPauseChildSource(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *child_ls, bool peer_flow,
                               bool parent_write)
{
    line_t *child_l    = child_ls->l;
    bool    was_paused = muxclientChildSourcePaused(child_ls);

    if (peer_flow)
    {
        child_ls->peer_flow_paused = true;
    }
    if (parent_write)
    {
        child_ls->parent_write_paused = true;
    }

    if (was_paused)
    {
        return true;
    }

    tunnelPrevDownStreamPause(t, child_l);
    return lineIsAlive(parent_l);
}

bool muxclientResumeChildSource(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *child_ls, bool peer_flow,
                                bool parent_write)
{
    line_t *child_l    = child_ls->l;
    bool    was_paused = muxclientChildSourcePaused(child_ls);

    if (peer_flow)
    {
        child_ls->peer_flow_paused = false;
        /* The fanout may not have visited this child yet. Preserve the gate
         * before deciding whether peer Resume permits its producer to run. */
        if (child_ls->parent->parent_state->output.sources_throttled && (was_paused || ! child_ls->source_starting))
        {
            if (! was_paused)
                return muxclientPauseChildSource(t, parent_l, child_ls, false, true);
            child_ls->parent_write_paused = true;
        }
    }
    if (parent_write)
    {
        child_ls->parent_write_paused = false;
    }

    if (! was_paused || muxclientChildSourcePaused(child_ls))
    {
        return true;
    }

    tunnelPrevDownStreamResume(t, child_l);
    return lineIsAlive(parent_l);
}

static bool muxclientCloseChildForQueueLimit(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                             muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls,
                                             const char *reason, size_t rejected_candidate_charge)
{
    const mux_cid_t cid           = child_ls->connection_id;
    const size_t    child_charge  = child_ls->pending_child_queue_charge;
    const size_t    parent_charge = parent_ls->pending_child_queue_charge;

    if (rejected_candidate_charge != 0)
    {
        LOGW("MuxClient: closing child cid %u because %s "
             "(child-retained-charge=%zu candidate-retained-charge=%zu parent-child-charge=%zu)",
             (unsigned int) cid,
             reason,
             child_charge,
             rejected_candidate_charge,
             parent_charge);
    }
    else
    {
        LOGW("MuxClient: closing child cid %u because %s "
             "(child-retained-charge=%zu parent-child-charge=%zu)",
             (unsigned int) cid,
             reason,
             child_charge,
             parent_charge);
    }

    /* Detach and destroy the child before submitting Close: a queued control
     * can cross high water and re-enter any producer during notification. */
    lineRef(parent_l);
    muxclientCloseChildKeepParent(t, ts, parent_l, parent_ls, child_ls, true);
    const bool parent_alive = lineIsAlive(parent_l) && parent_ls->parent_state != NULL && ! parent_ls->parent_finishing;
    lineUnref(parent_l);
    return parent_alive;
}

/*
 * Return the actual largest queued child. Children remain in ownership-list
 * insertion order; replacing on an equal size makes the stable tie-break prefer
 * the oldest attached child.
 */
static muxclient_lstate_t *muxclientFindLargestQueuedChild(muxclient_lstate_t *parent_ls, size_t *queued_charge_out)
{
    muxclient_lstate_t *largest      = NULL;
    size_t              largest_size = 0;

    for (muxclient_lstate_t *child_ls = parent_ls->child_next; child_ls != NULL; child_ls = child_ls->child_next)
    {
        const size_t queued_charge = child_ls->pending_child_queue_charge;
        if (queued_charge > 0 && queued_charge >= largest_size)
        {
            largest      = child_ls;
            largest_size = queued_charge;
        }
    }

    *queued_charge_out = largest_size;
    return largest;
}

/* Only pressure recovery scans children. Incoming assembly may require several
 * victims; every callback must leave a smaller total or this parent is closed. */
bool muxclientEnforceParentReceiveLimit(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t       *ts        = tunnelGetState(t);
    muxclient_lstate_t       *parent_ls = lineGetState(parent_l, t);
    muxclient_parent_state_t *state     = parent_ls->parent_state;
    if (state->receive_depth != 0 || state->receive_enforcing ||
        ! muxParentReceiveOverLimit(parent_ls->pending_child_queue_charge, state->read_stream, ts->parent_buffer_limit))
        return true;

    lineRef(parent_l);
    state->receive_enforcing = true;
    while (
        muxParentReceiveOverLimit(parent_ls->pending_child_queue_charge, state->read_stream, ts->parent_buffer_limit))
    {
        discard splicestreamCompact(state->read_stream);
        if (! muxParentReceiveOverLimit(
                parent_ls->pending_child_queue_charge, state->read_stream, ts->parent_buffer_limit))
            break;
        size_t  before = SIZE_MAX;
        discard muxTryParentReceiveCharge(parent_ls->pending_child_queue_charge, state->read_stream, &before);
        size_t  victim_charge;
        muxclient_lstate_t *victim = muxclientFindLargestQueuedChild(parent_ls, &victim_charge);
        if (victim == NULL)
        {
            LOGW("MuxClient: incoming assembly cannot fit parent receive limit (incoming=%zu children=%zu limit=%u)",
                 splicestreamCharge(state->read_stream),
                 parent_ls->pending_child_queue_charge,
                 ts->parent_buffer_limit);
            muxclientHandleParentLoss(t, parent_l, true);
            lineUnref(parent_l);
            return false;
        }
        if (! muxclientCloseChildForQueueLimit(
                t, parent_l, ts, parent_ls, victim, "parent receive queue capacity reached its limit", 0))
        {
            lineUnref(parent_l);
            return false;
        }
        // Close may re-enter input, remove siblings, quiesce, or destroy this parent.
        if (ts->worker_states[lineGetWID(parent_l)].quiescing)
        {
            state->receive_enforcing = false;
            lineUnref(parent_l);
            return false;
        }
        size_t after;
        if (! muxTryParentReceiveCharge(parent_ls->pending_child_queue_charge, state->read_stream, &after) ||
            after >= before)
        {
            LOGW("MuxClient: parent receive pressure cleanup made no progress (limit=%u)", ts->parent_buffer_limit);
            muxclientHandleParentLoss(t, parent_l, true);
            lineUnref(parent_l);
            return false;
        }
    }
    state->receive_enforcing = false;
    lineUnref(parent_l);
    return true;
}

bool muxclientQueueChildPayload(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls,
                                muxclient_lstate_t *child_ls, sbuf_t *buf)
{
    assert(child_ls->close_state == kMuxClientChildCloseOpen);
    assert(child_ls->parent == parent_ls);

    buf = muxPrepareRetainedCandidate(lineGetBufferPool(parent_l), buf, true);

    const size_t candidate_charge     = sbufGetQueueCharge(buf);
    const bool   child_add_overflows  = child_ls->pending_child_queue_charge > SIZE_MAX - candidate_charge;
    const bool   parent_add_overflows = parent_ls->pending_child_queue_charge > SIZE_MAX - candidate_charge;
    if (UNLIKELY(child_add_overflows || parent_add_overflows ||
                 muxQueueChargeWouldReachLimit(
                     child_ls->pending_child_queue_charge, candidate_charge, ts->child_buffer_limit)))
    {
        lineReuseBuffer(parent_l, buf);
        return muxclientCloseChildForQueueLimit(t,
                                                parent_l,
                                                ts,
                                                parent_ls,
                                                child_ls,
                                                child_add_overflows || parent_add_overflows
                                                    ? "retained queue-charge accounting cannot represent another entry"
                                                    : "another retained queue entry would reach its child limit",
                                                candidate_charge);
    }

    if (UNLIKELY(! bufferqueueTryPushBack(&child_ls->pending_child_data, &buf)))
    {
        lineReuseBuffer(parent_l, buf);
        return muxclientCloseChildForQueueLimit(
            t, parent_l, ts, parent_ls, child_ls, "its child queue could not reserve another entry", candidate_charge);
    }
    assert(sbufGetQueueCharge(buf) == candidate_charge);

    muxclientAddChildQueueCharge(child_ls, candidate_charge);
    muxclientAddParentPendingChildCharge(parent_ls, candidate_charge);

    return muxclientEnforceParentReceiveLimit(t, parent_l);
}

static bool muxclientHandleChildBufferAfterDrain(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                                 muxclient_lstate_t *parent_ls, line_t *child_l,
                                                 muxclient_lstate_t *child_ls)
{
    size_t pending_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);

    if (child_ls->close_state == kMuxClientChildCloseOpen && ! child_ls->paused && child_ls->flow_paused_sent &&
        pending_bytes < ts->child_buffer_resume_threshold)
    {
        if (! muxclientSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowResume))
        {
            return false;
        }
    }

    return true;
}

muxclient_child_drain_result_t muxclientDrainAttachedChild(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                                           line_t *child_l, muxclient_lstate_t *child_ls)
{
    muxclient_tstate_t *ts = tunnelGetState(t);

    assert(child_ls->parent == parent_ls);
    assert(child_ls->close_state != kMuxClientChildCloseParentGoneDraining);

    lineRef(parent_l);
    while (! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) > 0)
    {
        sbuf_t      *buf    = bufferqueuePopFront(&child_ls->pending_child_data);
        const size_t charge = sbufGetQueueCharge(buf);
        muxclientSubtractChildQueueCharge(child_ls, charge);
        muxclientSubtractParentPendingChildCharge(parent_ls, charge);

        if (! lineCallWithRefWithBuf(child_l, tunnelPrevDownStreamPayload, t, buf))
        {
            lineUnref(parent_l);
            return kMuxClientChildDrainChildGone;
        }

        if (! lineIsAlive(parent_l))
        {
            lineUnref(parent_l);
            return kMuxClientChildDrainParentGone;
        }

        child_ls = lineGetState(child_l, t);
        if (child_ls->close_state == kMuxClientChildCloseParentGoneDraining || child_ls->parent != parent_ls)
        {
            lineUnref(parent_l);
            return kMuxClientChildDrainParentGone;
        }

        if (child_ls->paused)
        {
            break;
        }

        if (! muxclientHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
        {
            lineUnref(parent_l);
            return kMuxClientChildDrainParentGone;
        }
    }

    if (! child_ls->paused && ! muxclientHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
    {
        lineUnref(parent_l);
        return kMuxClientChildDrainParentGone;
    }

    const muxclient_child_drain_result_t result =
        ! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) == 0
            ? kMuxClientChildDrainReadyToFinish
            : kMuxClientChildDrainBlocked;
    lineUnref(parent_l);
    return result;
}

static void muxclientRegisterDetachedChild(muxclient_tstate_t *ts, line_t *child_l, size_t queued_charge)
{
    const wid_t wid = lineGetWID(child_l);
    assert(lineIsOnCurrentEventWorker(child_l));
    assert(workerWIDIsRegistered(wid));

    if (UNLIKELY(ts->detached_child_counts == NULL || ts->detached_queued_charge == NULL || wid >= ts->workers_count ||
                 ts->detached_child_counts[wid] == UINT32_MAX ||
                 ts->detached_queued_charge[wid] > SIZE_MAX - queued_charge))
    {
        LOGF("MuxClient: detached retained queue-charge accounting overflow on worker %d", (int) wid);
        abortProgramNow(1);
    }

    ts->detached_child_counts[wid]++;
    ts->detached_queued_charge[wid] += queued_charge;
}

static void muxclientSubtractDetachedCharge(muxclient_tstate_t *ts, line_t *child_l, size_t charge)
{
    const wid_t wid = lineGetWID(child_l);
    assert(lineIsOnCurrentEventWorker(child_l));

    if (UNLIKELY(ts->detached_queued_charge == NULL || wid >= ts->workers_count ||
                 ts->detached_queued_charge[wid] < charge))
    {
        LOGF("MuxClient: detached retained queue-charge accounting underflow on worker %d", (int) wid);
        abortProgramNow(1);
    }
    ts->detached_queued_charge[wid] -= charge;
}

static void muxclientRemoveDetachedChild(muxclient_tstate_t *ts, line_t *child_l, muxclient_lstate_t *child_ls)
{
    const wid_t  wid             = lineGetWID(child_l);
    const size_t residual_charge = child_ls->pending_child_queue_charge;
    const size_t residual_count  = bufferqueueGetBufCount(&child_ls->pending_child_data);

    assert(lineIsOnCurrentEventWorker(child_l));
    assert(child_ls->close_state == kMuxClientChildCloseParentGoneDraining);
    assert(child_ls->parent == NULL);

    if (UNLIKELY((residual_charge == 0) != (residual_count == 0) || ts->detached_child_counts == NULL ||
                 ts->detached_queued_charge == NULL || wid >= ts->workers_count ||
                 ts->detached_child_counts[wid] == 0 || ts->detached_queued_charge[wid] < residual_charge))
    {
        LOGF("MuxClient: invalid detached child removal on worker %d", (int) wid);
        abortProgramNow(1);
    }

    ts->detached_queued_charge[wid] -= residual_charge;
    ts->detached_child_counts[wid]--;
    child_ls->pending_child_queue_charge = 0;

    if (residual_count != 0)
    {
        const size_t discarded = muxDiscardRetainedQueue(&child_ls->pending_child_data, lineGetBufferPool(child_l));
        if (UNLIKELY(discarded != residual_charge))
        {
            LOGF("Mux: detached child resource charge disagrees with queued ownership");
            abortProgramNow(1);
        }
    }

    /* A paused detached child may validly have an empty queue. */
    if (UNLIKELY(ts->detached_child_counts[wid] == 0 && ts->detached_queued_charge[wid] != 0))
    {
        LOGF("MuxClient: detached queue charge remained without a child on worker %d", (int) wid);
        abortProgramNow(1);
    }
}

muxclient_child_drain_result_t muxclientDrainDetachedChild(tunnel_t *t, line_t *child_l, muxclient_lstate_t *child_ls)
{
    muxclient_tstate_t *ts = tunnelGetState(t);

    assert(lineIsOnCurrentEventWorker(child_l));
    assert(child_ls->close_state == kMuxClientChildCloseParentGoneDraining);
    assert(child_ls->parent == NULL);

    while (! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) > 0)
    {
        sbuf_t      *buf    = bufferqueuePopFront(&child_ls->pending_child_data);
        const size_t charge = sbufGetQueueCharge(buf);
        muxclientSubtractChildQueueCharge(child_ls, charge);
        muxclientSubtractDetachedCharge(ts, child_l, charge);

        if (! lineCallWithRefWithBuf(child_l, tunnelPrevDownStreamPayload, t, buf))
        {
            return kMuxClientChildDrainChildGone;
        }

        child_ls = lineGetState(child_l, t);
        if (UNLIKELY(child_ls->close_state != kMuxClientChildCloseParentGoneDraining || child_ls->parent != NULL))
        {
            LOGF("MuxClient: detached child changed association while draining");
            abortProgramNow(1);
        }
    }

    return ! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) == 0
               ? kMuxClientChildDrainReadyToFinish
               : kMuxClientChildDrainBlocked;
}

void muxclientFinalizeDetachedChild(tunnel_t *t, line_t *child_l, muxclient_lstate_t *child_ls)
{
    assert(child_ls->close_state == kMuxClientChildCloseParentGoneDraining);
    assert(! child_ls->paused);
    assert(bufferqueueGetBufCount(&child_ls->pending_child_data) == 0);

    muxclientRemoveDetachedChild(tunnelGetState(t), child_l, child_ls);
    muxclientLinestateDestroy(child_ls);
    tunnelPrevDownStreamFinish(t, child_l);
}

void muxclientAbortDetachedChild(tunnel_t *t, line_t *child_l, muxclient_lstate_t *child_ls, bool notify_child_prev)
{
    muxclientRemoveDetachedChild(tunnelGetState(t), child_l, child_ls);
    muxclientLinestateDestroy(child_ls);
    if (notify_child_prev)
    {
        tunnelPrevDownStreamFinish(t, child_l);
    }
}

bool muxclientFinalizeAttachedPeerClose(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                        muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    assert(child_ls->close_state == kMuxClientChildClosePeerDraining);
    assert(child_ls->parent == parent_ls);
    assert(! child_ls->paused);
    assert(bufferqueueGetBufCount(&child_ls->pending_child_data) == 0);

    lineRef(parent_l);
    muxclientLeaveConnection(child_ls);
    muxclientLinestateDestroy(child_ls);
    tunnelPrevDownStreamFinish(t, child_l);

    if (! lineIsAlive(parent_l))
    {
        lineUnref(parent_l);
        return false;
    }

    if (muxclientParentShouldCloseWhenIdle(ts, parent_ls) && parent_ls->children_count == 0)
    {
        muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent_ls);
        lineUnref(parent_l);
        return false;
    }

    lineUnref(parent_l);
    return true;
}

bool muxclientBeginPeerCloseDrain(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls,
                                  muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;
    assert(child_ls->close_state == kMuxClientChildCloseOpen);

    const bool source_was_paused = muxclientChildSourcePaused(child_ls);
    child_ls->close_state        = kMuxClientChildClosePeerDraining;

    const muxclient_child_drain_result_t result =
        muxclientDrainAttachedChild(t, parent_l, parent_ls, child_l, child_ls);
    if (result == kMuxClientChildDrainChildGone || result == kMuxClientChildDrainParentGone)
    {
        return lineIsAlive(parent_l);
    }
    if (result == kMuxClientChildDrainReadyToFinish)
    {
        return muxclientFinalizeAttachedPeerClose(t, parent_l, ts, parent_ls, child_ls);
    }

    if (! source_was_paused)
    {
        lineRef(parent_l);
        discard    lineCallWithRef(child_l, tunnelPrevDownStreamPause, t);
        const bool parent_alive = lineIsAlive(parent_l);
        lineUnref(parent_l);
        return parent_alive;
    }
    return true;
}

static bool muxclientDetachedLimitReached(muxclient_tstate_t *ts, wid_t wid)
{
    return (ts->detached_buffer_limit != kMuxDetachedLimitUnlimited &&
            ts->detached_queued_charge[wid] >= (size_t) ts->detached_buffer_limit) ||
           (ts->detached_child_limit != kMuxDetachedLimitUnlimited &&
            ts->detached_child_counts[wid] >= ts->detached_child_limit);
}

void muxclientHandleParentLoss(tunnel_t *t, line_t *parent_l, bool notify_parent_next)
{
    muxclient_tstate_t *ts                = tunnelGetState(t);
    muxclient_lstate_t *parent_ls         = lineGetState(parent_l, t);
    const wid_t         wid               = lineGetWID(parent_l);
    uint32_t            detached_children = 0;
    size_t              detached_charge   = 0;

    /* A nested local failure cannot start another teardown. A real transport
     * Finish must still settle ownership immediately and suppress reflection. */
    if (parent_ls->parent_finishing && notify_parent_next)
        return;

    assert(lineIsOnCurrentEventWorker(parent_l));
    muxclientForgetParentSelection(ts, wid, parent_l);
    if (parent_ls->parent_state->owned)
    {
        muxclientUnregisterParent(ts, parent_ls);
    }

    lineRef(parent_l);
    parent_ls->parent_finishing = true;

    if (ts->worker_states[wid].quiescing)
    {
        while (lineIsAlive(parent_l) && parent_ls->parent_state != NULL && parent_ls->child_next != NULL)
        {
            muxclientCloseChildKeepParent(t, ts, parent_l, parent_ls, parent_ls->child_next, true);
            if (! lineIsAlive(parent_l) || parent_ls->parent_state == NULL)
            {
                lineUnref(parent_l);
                return;
            }
        }
        muxclientLinestateDestroy(parent_ls);
        if (notify_parent_next)
        {
            tunnelNextUpStreamFinish(t, parent_l);
        }
        if (lineIsAlive(parent_l))
        {
            lineDestroy(parent_l);
        }
        lineUnref(parent_l);
        return;
    }

    while (lineIsAlive(parent_l) && parent_ls->parent_state != NULL && parent_ls->child_next != NULL)
    {
        muxclient_lstate_t *child_ls          = parent_ls->child_next;
        line_t             *child_l           = child_ls->l;
        const bool          source_was_paused = muxclientChildSourcePaused(child_ls);
        const size_t        queued_charge     = child_ls->pending_child_queue_charge;

        assert(child_ls->close_state == kMuxClientChildCloseOpen ||
               child_ls->close_state == kMuxClientChildClosePeerDraining);
        child_ls->close_state = kMuxClientChildCloseParentGoneDraining;
        muxclientSubtractParentPendingChildCharge(parent_ls, queued_charge);
        muxclientLeaveConnection(child_ls);
        muxclientRegisterDetachedChild(ts, child_l, queued_charge);
        detached_children++;
        if (UNLIKELY(detached_charge > SIZE_MAX - queued_charge))
        {
            LOGF("MuxClient: parent-loss diagnostic charge overflow");
            abortProgramNow(1);
        }
        detached_charge += queued_charge;

        const muxclient_child_drain_result_t result = muxclientDrainDetachedChild(t, child_l, child_ls);
        if (result == kMuxClientChildDrainChildGone)
        {
            continue;
        }
        if (result == kMuxClientChildDrainReadyToFinish)
        {
            muxclientFinalizeDetachedChild(t, child_l, child_ls);
            continue;
        }
        if (UNLIKELY(result != kMuxClientChildDrainBlocked))
        {
            LOGF("MuxClient: invalid detached drain result during parent loss");
            abortProgramNow(1);
        }

        child_ls = lineGetState(child_l, t);
        if (muxclientDetachedLimitReached(ts, wid))
        {
            LOGW("MuxClient: aborting detached child cid %u at worker backlog limit "
                 "(child-retained-charge=%zu worker-children=%u worker-retained-charge=%zu "
                 "child-limit=%u charge-limit=%u)",
                 (unsigned int) child_ls->connection_id,
                 child_ls->pending_child_queue_charge,
                 ts->detached_child_counts[wid],
                 ts->detached_queued_charge[wid],
                 ts->detached_child_limit,
                 ts->detached_buffer_limit);
            muxclientAbortDetachedChild(t, child_l, child_ls, true);
            continue;
        }

        if (! source_was_paused)
        {
            discard lineCallWithRef(child_l, tunnelPrevDownStreamPause, t);
        }
    }

    if (! lineIsAlive(parent_l) || parent_ls->parent_state == NULL)
    {
        lineUnref(parent_l);
        return;
    }

    if (UNLIKELY(parent_ls->children_count != 0 || parent_ls->child_next != NULL ||
                 parent_ls->pending_child_queue_charge != 0))
    {
        LOGF("MuxClient: parent-loss transfer left attached child state behind");
        abortProgramNow(1);
    }

    LOGD("MuxClient: parent loss transferred detached-children=%u detached-retained-charge=%zu",
         detached_children,
         detached_charge);

    muxclientLinestateDestroy(parent_ls);
    if (notify_parent_next)
    {
        tunnelNextUpStreamFinish(t, parent_l);
    }
    if (lineIsAlive(parent_l))
    {
        lineDestroy(parent_l);
    }
    lineUnref(parent_l);
}

/* A physical reference is held by each caller of this predicate. A borrowed
 * parent's local state can already be gone while its owner unwinds Finish. */
static bool muxclientParentOutputAlive(tunnel_t *t, line_t *parent_l)
{
    if (! lineIsAlive(parent_l))
        return false;
    muxclient_lstate_t *parent = lineGetState(parent_l, t);
    return parent->parent_state != NULL && ! parent->parent_finishing;
}

/* Snapshot physical references only on a gate transition. A callback may remove
 * any sibling or attach new children; Init/Est completion handles new arrivals. */
static void muxclientNotifyParentGate(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t  *ts     = tunnelGetState(t);
    muxclient_lstate_t  *parent = lineGetState(parent_l, t);
    mux_parent_output_t *output = &parent->parent_state->output;
    if (output->notifying)
        return;
    output->notifying = true;
    for (;;)
    {
        const bool   throttled = output->sources_throttled;
        const size_t count     = parent->children_count;
        size_t       bytes     = 0;
        const bool   fits      = memoryTryComputeArraySize(count, sizeof(line_t *), &bytes);
        line_t     **children  = count && fits ? memoryAllocate(bytes) : NULL;
        if (count && children == NULL)
        {
            LOGE("MuxClient: unable to snapshot children for parent write pressure");
            muxclientHandleParentLoss(t, parent_l, true);
            return;
        }
        size_t n = 0;
        muxclient_lstate_t *snapshot_child = throttled ? parent->child_next : parent->parent_state->resume_cursor;
        for (; n < count; snapshot_child = snapshot_child->child_next ? snapshot_child->child_next : parent->child_next)
        {
            children[n++] = snapshot_child->l;
            lineRef(snapshot_child->l);
        }
        for (size_t i = 0; i < n; ++i)
        {
            if (muxclientParentOutputAlive(t, parent_l) && ! ts->worker_states[lineGetWID(parent_l)].quiescing &&
                output->sources_throttled == throttled && lineIsAlive(children[i]))
            {
                muxclient_lstate_t *child = lineGetState(children[i], t);
                if (child->is_child && child->parent == parent && ! child->source_starting)
                {
                    if (throttled)
                        discard muxclientPauseChildSource(t, parent_l, child, false, true);
                    else
                    {
                        parent->parent_state->resume_cursor =
                            child->child_next ? child->child_next : parent->child_next;
                        discard muxclientResumeChildSource(t, parent_l, child, false, true);
                    }
                }
            }
            lineUnref(children[i]);
        }
        memoryFree(children);
        if (! muxclientParentOutputAlive(t, parent_l))
            return;
        if (output->sources_throttled == throttled)
            break;
    }
    output->notifying = false;
}

void muxclientDrainParentOutput(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t *ts     = tunnelGetState(t);
    muxclient_lstate_t *parent = lineGetState(parent_l, t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing)
        return;
    mux_parent_output_t *output = &parent->parent_state->output;
    if (output->pumping)
        return;
    lineRef(parent_l);
    output->pumping = true;
    while (muxclientParentOutputAlive(t, parent_l) && ! ts->worker_states[lineGetWID(parent_l)].quiescing &&
           ! output->transport_paused)
    {
        /* Decide only before the next pop, using the previous callback's state. */
        if (output->sources_throttled && ! output->notifying && output->charge <= ts->parent_write_resume_threshold)
        {
            muxParentOutputSetThrottled(output, false, wloopNowLoopRunTime(getWorkerLoop(lineGetWID(parent_l))));
            muxclientNotifyParentGate(t, parent_l);
            continue;
        }
        if (! bufferqueueGetBufCount(&output->pending))
            break;
        sbuf_t *buf = muxParentOutputPop(output);
        tunnelNextUpStreamPayload(t, parent_l, buf);
    }
    const bool alive = muxclientParentOutputAlive(t, parent_l);
    if (alive)
        output->pumping = false;
    if (alive && ! output->notifying && parent->children_count == 0 && muxclientParentShouldCloseWhenIdle(ts, parent))
    {
        muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent);
    }
    lineUnref(parent_l);
}

bool muxclientSendParentOutput(tunnel_t *t, line_t *parent_l, sbuf_t *buf, muxclient_lstate_t *child, uint8_t flag)
{
    muxclient_tstate_t *ts     = tunnelGetState(t);
    muxclient_lstate_t *parent = lineGetState(parent_l, t);
    buffer_pool_t      *pool   = lineGetBufferPool(parent_l);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing)
    {
        bufferpoolReuseBuffer(pool, buf);
        return false;
    }
    lineRef(parent_l);
    mux_parent_output_t *output = &parent->parent_state->output;
    const bool           direct =
        ! output->transport_paused && ! output->pumping && bufferqueueGetBufCount(&output->pending) == 0;
    if (! direct)
    {
        buf = muxPrepareRetainedCandidate(pool, buf, false);
        if (! muxParentOutputEnqueue(output, &buf, ts->parent_write_limit))
        {
            const size_t candidate_charge = sbufGetQueueCharge(buf);
            const char  *reason =
                output->charge > ts->parent_write_limit || candidate_charge > ts->parent_write_limit - output->charge
                     ? "resource limit exceeded"
                     : "reservation refused";
            LOGE("MuxClient: parent write queue %s "
                 "(retained-charge=%zu candidate-charge=%zu limit=%u)",
                 reason,
                 output->charge,
                 candidate_charge,
                 ts->parent_write_limit);
            bufferpoolReuseBuffer(pool, buf);
            muxclientHandleParentLoss(t, parent_l, true);
            lineUnref(parent_l);
            return false;
        }
    }
    /* Admission and wire-state publication precede forwarding and gate fanout. */
    if (child != NULL)
    {
        if (flag == kMuxFlagData)
            child->open_frame_submitted = true;
        if (flag == kMuxFlagFlowPause)
            child->flow_paused_sent = true;
        if (flag == kMuxFlagFlowResume)
            child->flow_paused_sent = false;
    }
    if (direct)
    {
        output->pumping = true;
        tunnelNextUpStreamPayload(t, parent_l, buf);
        if (muxclientParentOutputAlive(t, parent_l))
            output->pumping = false;
    }
    else if (output->charge >= ts->parent_write_pause_threshold && ! output->sources_throttled)
    {
        muxParentOutputSetThrottled(output, true, wloopNowLoopRunTime(getWorkerLoop(lineGetWID(parent_l))));
        muxclientNotifyParentGate(t, parent_l);
    }
    if (muxclientParentOutputAlive(t, parent_l))
        muxclientDrainParentOutput(t, parent_l);
    const bool alive = muxclientParentOutputAlive(t, parent_l);
    lineUnref(parent_l);
    return alive;
}

void muxclientSendSpliceBatch(tunnel_t *t, line_t *parent_l, sbuf_t *input, muxclient_lstate_t *child)
{
    muxclient_tstate_t  *ts     = tunnelGetState(t);
    muxclient_lstate_t  *parent = lineGetState(parent_l, t);
    mux_parent_output_t *output = &parent->parent_state->output;
    lineRef(parent_l);
    if (! muxEncodeSpliceBatch(lineGetBufferPool(parent_l),
                               input,
                               child->connection_id,
                               ! child->open_frame_submitted,
                               output,
                               ts->parent_write_limit))
    {
        LOGE("MuxClient: complete splice batch exceeds parent limit or reservation failed");
        muxclientHandleParentLoss(t, parent_l, true);
        lineUnref(parent_l);
        return;
    }
    child->open_frame_submitted = true;
    if (output->charge >= ts->parent_write_pause_threshold && ! output->sources_throttled)
    {
        muxParentOutputSetThrottled(output, true, wloopNowLoopRunTime(getWorkerLoop(lineGetWID(parent_l))));
        muxclientNotifyParentGate(t, parent_l);
    }
    if (muxclientParentOutputAlive(t, parent_l))
        muxclientDrainParentOutput(t, parent_l);
    lineUnref(parent_l);
}
