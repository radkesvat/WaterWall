#include "structure.h"

#include "loggers/network_logger.h"

static uint64_t muxserverMemoryAdmissionPack(uint64_t generation, bool closed)
{
    if (UNLIKELY(generation > (UINT64_MAX >> 1U)))
    {
        LOGF("MuxServer: memory admission generation is not representable");
        abortProgramNow(1);
    }
    return (generation << 1U) | (closed ? 1U : 0U);
}

muxserver_memory_admission_t muxserverEvaluateMemoryAdmission(muxserver_tstate_t *ts)
{
    system_memory_snapshot_t              snapshot = {0};
    const system_memory_snapshot_status_t status   = systemMemorySnapshotGet(&snapshot);
    muxserver_memory_admission_t          decision = {
                 .effective_ceiling   = min(ts->max_live_children, ts->memory_fallback_max_live_children),
                 .snapshot_generation = snapshot.generation,
                 .snapshot_status     = status,
                 .reason              = kMuxServerAdmissionAllowedFallback,
                 .permits_memory      = true,
                 .gate_transitioned   = false,
                 .gate_closed         = false,
    };

    uint64_t observed = atomicLoadU64Relaxed(&ts->memory_admission_state);
    if (status != kSystemMemorySnapshotFresh)
    {
        decision.gate_closed = (observed & 1U) != 0;
        if (decision.gate_closed)
        {
            decision.permits_memory = false;
            decision.reason         = kMuxServerAdmissionRejectedPressure;
        }
        return decision;
    }

    decision.effective_ceiling = ts->max_live_children;
    for (;;)
    {
        const uint64_t observed_generation = observed >> 1U;
        const bool     was_closed          = (observed & 1U) != 0;
        if (snapshot.generation <= observed_generation)
        {
            decision.gate_closed = was_closed;
            break;
        }

        const uint32_t high_basis_points = ts->memory_high_watermark_percent * 100U;
        const uint32_t low_basis_points  = ts->memory_low_watermark_percent * 100U;
        const bool     high_pressure =
            snapshot.host_used_basis_points >= high_basis_points ||
            (snapshot.cgroup_limited && snapshot.cgroup_used_basis_points >= high_basis_points) ||
            ((uint64_t) ts->memory_reserve != 0 && snapshot.effective_available_bytes <= (uint64_t) ts->memory_reserve);
        const bool recovered =
            snapshot.host_used_basis_points <= low_basis_points &&
            (! snapshot.cgroup_limited || snapshot.cgroup_used_basis_points <= low_basis_points) &&
            ((uint64_t) ts->memory_reserve == 0 || snapshot.effective_available_bytes > (uint64_t) ts->memory_reserve);
        const bool     desired_closed = was_closed ? ! recovered : high_pressure;
        const uint64_t desired        = muxserverMemoryAdmissionPack(snapshot.generation, desired_closed);
        if (atomicCompareExchangeU64(&ts->memory_admission_state, &observed, desired))
        {
            decision.gate_closed       = desired_closed;
            decision.gate_transitioned = desired_closed != was_closed;
            break;
        }
    }

    decision.permits_memory = ! decision.gate_closed;
    decision.reason = decision.gate_closed ? kMuxServerAdmissionRejectedPressure : kMuxServerAdmissionAllowedFresh;
    return decision;
}

bool muxserverTryReserveLiveChildSlot(muxserver_tstate_t *ts, uint32_t effective_ceiling)
{
    assert(effective_ceiling > 0 && effective_ceiling <= ts->max_live_children);

    w_atomic_uint_value_t count = atomicLoadRelaxed(&ts->live_children_count);
    for (;;)
    {
        if (count >= effective_ceiling)
        {
            return false;
        }
        if (atomicCompareExchangeExplicit(
                &ts->live_children_count, &count, count + 1U, memory_order_relaxed, memory_order_relaxed))
        {
            return true;
        }
    }
}

void muxserverReleaseLiveChildSlot(muxserver_tstate_t *ts)
{
    const w_atomic_uint_value_t previous = atomicSubExplicit(&ts->live_children_count, 1U, memory_order_relaxed);
    if (UNLIKELY(previous == 0))
    {
        LOGF("MuxServer: aggregate live-child reservation underflow");
        abortProgramNow(1);
    }
}

bool muxserverConsumeRejectedOpenToken(muxserver_lstate_t *parent_ls, uint64_t now_ms)
{
    assert(! parent_ls->is_child && parent_ls->parent_state != NULL);
    muxserver_rejection_bucket_t *bucket = &parent_ls->parent_state->rejection_bucket;

    if (bucket->last_refill_ms == 0)
    {
        bucket->last_refill_ms = now_ms;
    }
    else if (now_ms < bucket->last_refill_ms)
    {
        bucket->last_refill_ms = now_ms;
    }
    else
    {
        const uint64_t steps = (now_ms - bucket->last_refill_ms) / 1000U;
        if (steps != 0)
        {
            const uint64_t needed =
                (kMuxServerRejectedOpenBurst - bucket->tokens + kMuxServerRejectedOpenRefillPerSecond - 1U) /
                kMuxServerRejectedOpenRefillPerSecond;
            if (steps >= needed)
            {
                bucket->tokens = kMuxServerRejectedOpenBurst;
            }
            else
            {
                bucket->tokens += (uint32_t) steps * kMuxServerRejectedOpenRefillPerSecond;
            }
            bucket->last_refill_ms += steps * 1000U;
        }
    }

    if (bucket->tokens == 0)
    {
        return false;
    }
    bucket->tokens--;
    return true;
}

muxserver_worker_state_t *muxserverGetWorkerState(tunnel_t *t, line_t *line)
{
    muxserver_tstate_t *ts  = tunnelGetState(t);
    const wid_t         wid = lineGetWID(line);
    assert(lineIsOnCurrentEventWorker(line));
    if (UNLIKELY(! workerWIDIsEventWorker(wid) || wid >= ts->workers_count))
    {
        LOGF("MuxServer: invalid worker %d for worker-local child state", (int) wid);
        abortProgramNow(1);
    }
    return &ts->worker_states[wid];
}

static hash_t muxserverChildIdleKey(const line_t *child_l)
{
    _Static_assert(sizeof(uintptr_t) <= sizeof(hash_t), "MuxServer child pointers must fit idle keys");
    return (hash_t) (uintptr_t) child_l;
}

static void muxserverCloseShutdownChild(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                        muxserver_lstate_t *child_ls, bool notify_child_next)
{
    line_t *child_l = child_ls->l;
    lineRef(child_l);
    muxserverLeaveConnection(child_ls);
    discard muxserverReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);
    muxserverLinestateDestroy(t, child_ls);
    if (notify_child_next)
    {
        tunnelNextUpStreamFinish(t, child_l);
    }
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }
    lineUnref(child_l);
}

static void muxserverOnChildIdleExpire(local_idle_item_t *item)
{
    muxserver_lstate_t *child_ls = item->userdata;
    tunnel_t           *t        = child_ls->t;
    line_t             *child_l  = child_ls->l;
    muxserver_tstate_t *ts       = tunnelGetState(t);
    const mux_cid_t     cid      = child_ls->connection_id;
    const bool          active   = child_ls->child_has_payload_activity;
    const wid_t         wid      = lineGetWID(child_l);
    local_idle_table_t *table    = item->table;

    assert(child_ls->is_child && child_ls->child_idle_item == item);
    const bool natural_expiry = item->expiring && ! item->removed && table != NULL;
    const bool drain_expiry   = ! item->expiring && item->removed && table == NULL;
    if (UNLIKELY(! natural_expiry && ! drain_expiry))
    {
        LOGF("MuxServer: child idle callback entered with an invalid item lifecycle");
        abortProgramNow(1);
    }

    child_ls->child_idle_item = NULL;
    if (natural_expiry && UNLIKELY(! localidletableRemoveIdleItem(table, item)))
    {
        LOGF("MuxServer: naturally expiring child idle item could not be detached");
        abortProgramNow(1);
    }

    /* The item is logically invalid after detach. Child destruction and the
     * Close callback below may immediately recycle this line address and arm a
     * replacement item with the same pointer key. */

    if (! drain_expiry && atomicLogRateLimiterShouldLog(&ts->idle_expiry_log_limiter, kMuxServerAdmissionLogIntervalMs))
    {
        LOGW("MuxServer: expiring %s idle child cid %u on worker %u",
             active ? "active" : "initial",
             (unsigned int) cid,
             (unsigned int) wid);
    }

    if (child_ls->close_state == kMuxServerChildCloseParentGoneDraining)
    {
        muxserverAbortDetachedChild(t, child_l, child_ls, true);
        return;
    }

    muxserver_lstate_t *parent_ls = child_ls->parent;
    assert(parent_ls != NULL);
    if (drain_expiry)
    {
        muxserverCloseShutdownChild(t, parent_ls->l, parent_ls, child_ls, true);
        return;
    }
    muxserverCloseChildKeepParent(t, parent_ls->l, parent_ls, child_ls, true);
}

void muxserverArmChildIdle(tunnel_t *t, muxserver_lstate_t *child_ls)
{
    assert(child_ls->is_child && child_ls->child_idle_item == NULL);
    muxserver_tstate_t       *ts           = tunnelGetState(t);
    muxserver_worker_state_t *worker_state = muxserverGetWorkerState(t, child_ls->l);
    if (worker_state->child_idle_table == NULL)
    {
        worker_state->child_idle_table = localIdleTableCreate(getWorkerLoop(lineGetWID(child_ls->l)));
    }

    child_ls->child_idle_item = localidletableCreateItem(worker_state->child_idle_table,
                                                         muxserverChildIdleKey(child_ls->l),
                                                         child_ls,
                                                         muxserverOnChildIdleExpire,
                                                         ts->initial_child_idle_timeout_ms);
    if (UNLIKELY(child_ls->child_idle_item == NULL))
    {
        LOGF("MuxServer: duplicate child idle key");
        abortProgramNow(1);
    }
}

void muxserverRefreshChildIdle(tunnel_t *t, muxserver_lstate_t *child_ls)
{
    assert(child_ls->is_child && child_ls->child_idle_item != NULL);
    muxserver_tstate_t       *ts           = tunnelGetState(t);
    muxserver_worker_state_t *worker_state = muxserverGetWorkerState(t, child_ls->l);
    if (UNLIKELY(worker_state->child_idle_table == NULL))
    {
        LOGF("MuxServer: active child has no worker idle table");
        abortProgramNow(1);
    }
    child_ls->child_has_payload_activity = true;
    localidletableKeepIdleItemForAtleast(
        worker_state->child_idle_table, child_ls->child_idle_item, ts->active_child_idle_timeout_ms);
}

void muxserverJoinConnection(muxserver_lstate_t *parent, muxserver_lstate_t *child)
{
    assert(child != NULL && parent != NULL && child->is_child && (parent->is_child == false));
    if (UNLIKELY(parent->parent_state == NULL || parent->children_count == UINT32_MAX ||
                 muxserverFindChildByConnectionId(parent, child->connection_id) != NULL))
    {
        LOGF("MuxServer: duplicate CID insertion or parent child-count overflow");
        abortProgramNow(1);
    }
    if (UNLIKELY(
            ! muxserver_child_map_t_insert(&parent->parent_state->child_map, child->connection_id, child).inserted))
    {
        LOGF("MuxServer: failed to publish child CID index entry");
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

    parent->children_count++;
}

void muxserverLeaveConnection(muxserver_lstate_t *child)
{
    if (UNLIKELY(child == NULL || ! child->is_child || child->parent == NULL))
    {
        LOGF("MuxServer: attempted to unlink a child without a live parent link");
        abortProgramNow(1);
    }

    muxserver_lstate_t        *parent = child->parent;
    muxserver_child_map_t_iter indexed =
        muxserver_child_map_t_find(&parent->parent_state->child_map, child->connection_id);
    if (UNLIKELY(indexed.ref == muxserver_child_map_t_end(&parent->parent_state->child_map).ref ||
                 indexed.ref->second != child))
    {
        LOGF("MuxServer: child CID index disagrees with ownership list");
        abortProgramNow(1);
    }
    muxserver_child_map_t_erase_at(&parent->parent_state->child_map, indexed);

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
        LOGF("MuxServer: parent child-count underflow");
        abortProgramNow(1);
    }
    child->parent->children_count--;

    child->parent     = NULL;
    child->child_prev = NULL;
    child->child_next = NULL;
}

muxserver_lstate_t *muxserverFindChildByConnectionId(muxserver_lstate_t *parent, mux_cid_t cid)
{
    assert(parent != NULL && ! parent->is_child && parent->parent_state != NULL);
    muxserver_child_map_t_iter found = muxserver_child_map_t_find(&parent->parent_state->child_map, cid);
    return found.ref == muxserver_child_map_t_end(&parent->parent_state->child_map).ref ? NULL : found.ref->second;
}

typedef struct muxserver_parent_stats_s
{
    uint32_t parent_write_paused;
    uint32_t child_read_paused;
    uint32_t child_write_paused;
    uint32_t children_close_pending;
} muxserver_parent_stats_t;

static void muxserverCollectParentStats(muxserver_lstate_t *parent_ls, muxserver_parent_stats_t *stats)
{
    memoryZero(stats, sizeof(*stats));

    for (muxserver_lstate_t *child_ls = parent_ls->child_next; child_ls != NULL; child_ls = child_ls->child_next)
    {
        if (child_ls->peer_flow_paused || child_ls->parent_write_paused)
        {
            stats->child_read_paused++;
        }
        if (child_ls->parent_write_paused)
        {
            stats->parent_write_paused++;
        }
        if (child_ls->paused)
        {
            stats->child_write_paused++;
        }
        if (child_ls->close_state == kMuxServerChildClosePeerDraining)
        {
            stats->children_close_pending++;
        }
    }
}

static void muxserverParentStatsLogTask(tunnel_t *t, line_t *parent_l)
{
    muxserver_tstate_t *ts        = tunnelGetState(t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing)
    {
        return;
    }

    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

    if (! ts->log_main_line_stats || parent_ls->is_child)
    {
        return;
    }

    muxserver_parent_stats_t stats;
    muxserverCollectParentStats(parent_ls, &stats);

    LOGI("MuxServer: main line stats wid=%u parent-line-write-paused=%s parent-line-read-paused=no "
         "children-count=%u children-close-pending=%u childs-read-paused=%u childs-write-paused=%u "
         "parent-child-queue-charge=%zu parent-input-queue-charge=%zu",
         (unsigned int) lineGetWID(parent_l),
         boolToYesNo(stats.parent_write_paused > 0),
         parent_ls->children_count,
         stats.children_close_pending,
         stats.child_read_paused,
         stats.child_write_paused,
         parent_ls->pending_child_queue_charge,
         splicestreamCharge(parent_ls->parent_state->read_stream));

    if (! parent_ls->parent_finishing)
    {
        /* Optional statistics sampling is intentionally lossy under pressure. */
        const line_task_submit_result_e result =
            lineScheduleDelayedTask(parent_l, muxserverParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t, NULL);
        discard result;
    }
}

void muxserverScheduleParentStatsLog(tunnel_t *t, line_t *parent_l)
{
    muxserver_tstate_t *ts = tunnelGetState(t);
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
        lineScheduleDelayedTask(parent_l, muxserverParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t, NULL);
    discard result;
}

static void muxserverCloseChildKeepParentImpl(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                              muxserver_lstate_t *child_ls, bool notify_child_next)
{
    if (muxserverGetWorkerState(t, child_ls->l)->quiescing)
    {
        muxserverCloseShutdownChild(t, parent_l, parent_ls, child_ls, notify_child_next);
        return;
    }

    line_t         *child_l     = child_ls->l;
    const mux_cid_t cid         = child_ls->connection_id;
    const bool      notify_peer = child_ls->close_state == kMuxServerChildCloseOpen;

    muxserverLeaveConnection(child_ls);

    const bool parent_alive = muxserverReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);

    if (! parent_alive || parent_ls->parent_finishing || ! notify_peer)
    {
        // no Close frame can be written; the peer learns about the close from the dying parent connection
        muxserverLinestateDestroy(t, child_ls);
        if (notify_child_next)
        {
            tunnelNextUpStreamFinish(t, child_l);
        }
        if (lineIsAlive(child_l))
        {
            lineDestroy(child_l);
        }
        return;
    }

    buffer_pool_t *pool             = lineGetBufferPool(parent_l);
    sbuf_t        *finishpacket_buf = muxParentOutputControlBuffer(pool);
    muxMakeMuxFrame(finishpacket_buf, cid, kMuxFlagClose);

    muxserverLinestateDestroy(t, child_ls);

    if (notify_child_next)
    {
        tunnelNextUpStreamFinish(t, child_l);
    }

    // MuxServer created this child line, so MuxServer destroys it
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }

    if (! lineIsAlive(parent_l) || parent_ls->parent_state == NULL || parent_ls->parent_finishing)
    {
        bufferpoolReuseBuffer(pool, finishpacket_buf);
        return;
    }

    discard muxserverSendParentOutput(t, parent_l, finishpacket_buf, NULL, kMuxFlagClose);
}

void muxserverCloseChildKeepParent(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                   muxserver_lstate_t *child_ls, bool notify_child_next)
{
    lineRef(parent_l);
    muxserverCloseChildKeepParentImpl(t, parent_l, parent_ls, child_ls, notify_child_next);
    lineUnref(parent_l);
}

static void muxserverAddChildQueueCharge(muxserver_lstate_t *child_ls, size_t charge)
{
    assert(child_ls != NULL && child_ls->is_child);
    if (UNLIKELY(child_ls->pending_child_queue_charge > SIZE_MAX - charge))
    {
        LOGF("MuxServer: child retained queue-charge accounting overflow");
        abortProgramNow(1);
    }

    child_ls->pending_child_queue_charge += charge;
}

static void muxserverSubtractChildQueueCharge(muxserver_lstate_t *child_ls, size_t charge)
{
    assert(child_ls != NULL && child_ls->is_child);
    if (UNLIKELY(child_ls->pending_child_queue_charge < charge))
    {
        LOGF("MuxServer: child retained queue-charge accounting underflow");
        abortProgramNow(1);
    }

    child_ls->pending_child_queue_charge -= charge;
}

static void muxserverAddParentPendingChildCharge(muxserver_lstate_t *parent_ls, size_t charge)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    if (UNLIKELY(parent_ls->pending_child_queue_charge > SIZE_MAX - charge))
    {
        LOGF("MuxServer: parent retained child-queue charge accounting overflow");
        abortProgramNow(1);
    }

    parent_ls->pending_child_queue_charge += charge;
}

static void muxserverSubtractParentPendingChildCharge(muxserver_lstate_t *parent_ls, size_t charge)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    if (UNLIKELY(parent_ls->pending_child_queue_charge < charge))
    {
        LOGF("MuxServer: parent retained child-queue charge accounting underflow");
        abortProgramNow(1);
    }

    parent_ls->pending_child_queue_charge -= charge;
}

static void muxserverReleaseChildPendingCharge(tunnel_t *t, muxserver_lstate_t *parent_ls, muxserver_lstate_t *child_ls)
{
    discard      t;
    const size_t pending_charge = child_ls->pending_child_queue_charge;
    const size_t pending_count  = bufferqueueGetBufCount(&child_ls->pending_child_data);
    if (UNLIKELY((pending_charge == 0) != (pending_count == 0)))
    {
        LOGF("MuxServer: attached child queue count/charge invariant failed during release");
        abortProgramNow(1);
    }
    if (pending_charge == 0)
    {
        return;
    }

    muxserverSubtractParentPendingChildCharge(parent_ls, pending_charge);
    child_ls->pending_child_queue_charge = 0;
    const size_t discarded = muxDiscardRetainedQueue(&child_ls->pending_child_data, lineGetBufferPool(child_ls->l));
    if (UNLIKELY(discarded != pending_charge))
    {
        LOGF("Mux: attached child resource charge disagrees with queued ownership");
        abortProgramNow(1);
    }
}

bool muxserverSendControlFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                               mux_cid_t cid, uint8_t flag)
{
    if (parent_ls->parent_finishing)
        return false;
    muxserver_lstate_t *child       = lineGetState(child_l, t);
    buffer_pool_t      *pool        = lineGetBufferPool(parent_l);
    sbuf_t             *control_buf = muxParentOutputControlBuffer(pool);
    muxMakeMuxFrame(control_buf, cid, flag);
    lineRef(child_l);
    const bool parent_alive = muxserverSendParentOutput(t, parent_l, control_buf, child, flag);
    const bool child_alive = lineIsAlive(child_l);
    lineUnref(child_l);
    return parent_alive && child_alive;
}

bool muxserverMaybeSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                      muxserver_lstate_t *parent_ls, line_t *child_l, muxserver_lstate_t *child_ls)
{
    if (bufferqueueGetBufLen(&child_ls->pending_child_data) < ts->child_buffer_pause_tolerance)
    {
        return true;
    }

    return muxserverSendChildFlowPause(t, parent_l, parent_ls, child_l, child_ls);
}

bool muxserverSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                                 muxserver_lstate_t *child_ls)
{
    if (parent_ls->parent_finishing || child_ls->close_state != kMuxServerChildCloseOpen || child_ls->flow_paused_sent)
    {
        return true;
    }

    return muxserverSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowPause);
}

/*
 * Queue pressure must not pause reads on the shared parent transport. Such a pause
 * blocks every child on the parent until the particular local child that caused it
 * starts draining again. Per-child FlowPause/FlowResume already asks the peer to stop
 * producing for that cid; the aggregate memory bound below protects the process
 * without turning one indefinitely blocked destination into a parent-wide stall.
 */
bool muxserverReleaseParentInputForChildClose(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                              muxserver_lstate_t *child_ls)
{
    muxserverReleaseChildPendingCharge(t, parent_ls, child_ls);
    return lineIsAlive(parent_l);
}

static bool muxserverChildSourcePaused(muxserver_lstate_t *child_ls)
{
    return child_ls->peer_flow_paused || child_ls->parent_write_paused ||
           child_ls->close_state != kMuxServerChildCloseOpen;
}

bool muxserverPauseChildSource(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *child_ls, bool peer_flow,
                               bool parent_write)
{
    line_t *child_l    = child_ls->l;
    bool    was_paused = muxserverChildSourcePaused(child_ls);

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

    tunnelNextUpStreamPause(t, child_l);
    return lineIsAlive(parent_l);
}

bool muxserverResumeChildSource(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *child_ls, bool peer_flow,
                                bool parent_write)
{
    line_t *child_l    = child_ls->l;
    bool    was_paused = muxserverChildSourcePaused(child_ls);

    if (peer_flow)
    {
        child_ls->peer_flow_paused = false;
        /* The fanout may not have visited this child yet. Preserve the gate
         * before deciding whether peer Resume permits its producer to run. */
        if (child_ls->parent->parent_state->output.sources_throttled && (was_paused || ! child_ls->source_starting))
        {
            if (! was_paused)
                return muxserverPauseChildSource(t, parent_l, child_ls, false, true);
            child_ls->parent_write_paused = true;
        }
    }
    if (parent_write)
    {
        child_ls->parent_write_paused = false;
    }

    if (! was_paused || muxserverChildSourcePaused(child_ls))
    {
        return true;
    }

    tunnelNextUpStreamResume(t, child_l);
    return lineIsAlive(parent_l);
}

static bool muxserverCloseChildForQueueLimit(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                             muxserver_lstate_t *child_ls, const char *reason,
                                             size_t rejected_candidate_charge)
{
    const mux_cid_t cid           = child_ls->connection_id;
    const size_t    child_charge  = child_ls->pending_child_queue_charge;
    const size_t    parent_charge = parent_ls->pending_child_queue_charge;

    if (rejected_candidate_charge != 0)
    {
        LOGW("MuxServer: closing child cid %u because %s "
             "(child-retained-charge=%zu candidate-retained-charge=%zu parent-child-charge=%zu)",
             (unsigned int) cid,
             reason,
             child_charge,
             rejected_candidate_charge,
             parent_charge);
    }
    else
    {
        LOGW("MuxServer: closing child cid %u because %s "
             "(child-retained-charge=%zu parent-child-charge=%zu)",
             (unsigned int) cid,
             reason,
             child_charge,
             parent_charge);
    }

    /* Detach and destroy the child before submitting Close: a queued control
     * can cross high water and re-enter any producer during notification. */
    lineRef(parent_l);
    muxserverCloseChildKeepParent(t, parent_l, parent_ls, child_ls, true);
    const bool parent_alive = lineIsAlive(parent_l) && parent_ls->parent_state != NULL && ! parent_ls->parent_finishing;
    lineUnref(parent_l);
    return parent_alive;
}

/*
 * Return the actual largest queued child. Children remain in ownership-list
 * insertion order; replacing on an equal size makes the stable tie-break prefer
 * the oldest attached child.
 */
static muxserver_lstate_t *muxserverFindLargestQueuedChild(muxserver_lstate_t *parent_ls, size_t *queued_charge_out)
{
    muxserver_lstate_t *largest      = NULL;
    size_t              largest_size = 0;

    for (muxserver_lstate_t *child_ls = parent_ls->child_next; child_ls != NULL; child_ls = child_ls->child_next)
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
bool muxserverEnforceParentReceiveLimit(tunnel_t *t, line_t *parent_l)
{
    muxserver_tstate_t       *ts        = tunnelGetState(t);
    muxserver_lstate_t       *parent_ls = lineGetState(parent_l, t);
    muxserver_parent_state_t *state     = parent_ls->parent_state;
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
        muxserver_lstate_t *victim = muxserverFindLargestQueuedChild(parent_ls, &victim_charge);
        if (victim == NULL)
        {
            LOGW("MuxServer: incoming assembly cannot fit parent receive limit (incoming=%zu children=%zu limit=%u)",
                 splicestreamCharge(state->read_stream),
                 parent_ls->pending_child_queue_charge,
                 ts->parent_buffer_limit);
            muxserverHandleParentLoss(t, parent_l, true);
            lineUnref(parent_l);
            return false;
        }
        if (! muxserverCloseChildForQueueLimit(
                t, parent_l, parent_ls, victim, "parent receive queue capacity reached its limit", 0))
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
            LOGW("MuxServer: parent receive pressure cleanup made no progress (limit=%u)", ts->parent_buffer_limit);
            muxserverHandleParentLoss(t, parent_l, true);
            lineUnref(parent_l);
            return false;
        }
    }
    state->receive_enforcing = false;
    lineUnref(parent_l);
    return true;
}

bool muxserverQueueChildPayload(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts, muxserver_lstate_t *parent_ls,
                                muxserver_lstate_t *child_ls, sbuf_t *buf)
{
    assert(child_ls->close_state == kMuxServerChildCloseOpen);
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
        return muxserverCloseChildForQueueLimit(t,
                                                parent_l,
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
        return muxserverCloseChildForQueueLimit(
            t, parent_l, parent_ls, child_ls, "its child queue could not reserve another entry", candidate_charge);
    }
    assert(sbufGetQueueCharge(buf) == candidate_charge);

    muxserverAddChildQueueCharge(child_ls, candidate_charge);
    muxserverAddParentPendingChildCharge(parent_ls, candidate_charge);

    // Control submission can close this child during parent-gate notification.
    // The parser can still process sibling frames if the parent survives.
    lineRef(parent_l);
    discard muxserverMaybeSendChildFlowPause(t, parent_l, ts, parent_ls, child_ls->l, child_ls);
    bool    keep_parsing = lineIsAlive(parent_l) && parent_ls->parent_state != NULL && ! parent_ls->parent_finishing &&
                        ! ts->worker_states[lineGetWID(parent_l)].quiescing;
    if (keep_parsing)
    {
        keep_parsing = muxserverEnforceParentReceiveLimit(t, parent_l);
    }
    lineUnref(parent_l);
    return keep_parsing;
}

static bool muxserverHandleChildBufferAfterDrain(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                                 muxserver_lstate_t *parent_ls, line_t *child_l,
                                                 muxserver_lstate_t *child_ls)
{
    size_t pending_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);

    if (child_ls->close_state == kMuxServerChildCloseOpen && ! child_ls->paused && child_ls->flow_paused_sent &&
        pending_bytes < ts->child_buffer_resume_threshold)
    {
        if (! muxserverSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowResume))
        {
            return false;
        }
    }

    return true;
}

muxserver_child_drain_result_t muxserverDrainAttachedChild(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                                           line_t *child_l, muxserver_lstate_t *child_ls)
{
    muxserver_tstate_t *ts = tunnelGetState(t);

    assert(child_ls->parent == parent_ls);
    assert(child_ls->close_state != kMuxServerChildCloseParentGoneDraining);

    lineRef(parent_l);
    while (! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) > 0)
    {
        sbuf_t      *buf    = bufferqueuePopFront(&child_ls->pending_child_data);
        const size_t charge = sbufGetQueueCharge(buf);
        muxserverSubtractChildQueueCharge(child_ls, charge);
        muxserverSubtractParentPendingChildCharge(parent_ls, charge);

        if (! lineCallWithRefWithBuf(child_l, tunnelNextUpStreamPayload, t, buf))
        {
            lineUnref(parent_l);
            return kMuxServerChildDrainChildGone;
        }

        if (! lineIsAlive(parent_l))
        {
            lineUnref(parent_l);
            return kMuxServerChildDrainParentGone;
        }

        child_ls = lineGetState(child_l, t);
        if (child_ls->close_state == kMuxServerChildCloseParentGoneDraining || child_ls->parent != parent_ls)
        {
            lineUnref(parent_l);
            return kMuxServerChildDrainParentGone;
        }

        if (child_ls->paused)
        {
            break;
        }

        if (! muxserverHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
        {
            lineUnref(parent_l);
            return kMuxServerChildDrainParentGone;
        }
    }

    if (! child_ls->paused && ! muxserverHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
    {
        lineUnref(parent_l);
        return kMuxServerChildDrainParentGone;
    }

    const muxserver_child_drain_result_t result =
        ! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) == 0
            ? kMuxServerChildDrainReadyToFinish
            : kMuxServerChildDrainBlocked;
    lineUnref(parent_l);
    return result;
}

muxserver_detached_registry_t *muxserverGetDetachedRegistry(tunnel_t *t, line_t *child_l)
{
    muxserver_tstate_t *ts  = tunnelGetState(t);
    const wid_t         wid = lineGetWID(child_l);

    assert(lineIsOnCurrentEventWorker(child_l));
    if (UNLIKELY(! workerWIDIsRegistered(wid) || wid >= ts->workers_count))
    {
        LOGF("MuxServer: invalid worker %d for detached child registry", (int) wid);
        abortProgramNow(1);
    }
    return &ts->worker_states[wid].detached_registry;
}

static void muxserverRegisterDetachedChild(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls,
                                           size_t queued_charge)
{
    muxserver_detached_registry_t *registry = muxserverGetDetachedRegistry(t, child_l);

    assert(child_ls->parent == NULL);
    assert(child_ls->close_state == kMuxServerChildCloseParentGoneDraining);
    if (UNLIKELY(child_ls->detached_registered || child_ls->detached_prev != NULL || child_ls->detached_next != NULL ||
                 registry->count == UINT32_MAX || registry->queued_charge > SIZE_MAX - queued_charge))
    {
        LOGF("MuxServer: duplicate detached registration or retained queue-charge accounting overflow");
        abortProgramNow(1);
    }

    child_ls->detached_prev = NULL;
    child_ls->detached_next = registry->head;
    if (registry->head != NULL)
    {
        registry->head->detached_prev = child_ls;
    }
    registry->head                = child_ls;
    child_ls->detached_registered = true;
    registry->count++;
    registry->queued_charge += queued_charge;
}

static void muxserverSubtractDetachedCharge(tunnel_t *t, line_t *child_l, size_t charge)
{
    muxserver_detached_registry_t *registry = muxserverGetDetachedRegistry(t, child_l);
    if (UNLIKELY(registry->queued_charge < charge))
    {
        LOGF("MuxServer: detached retained queue-charge accounting underflow");
        abortProgramNow(1);
    }
    registry->queued_charge -= charge;
}

static void muxserverRemoveDetachedChild(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls)
{
    muxserver_detached_registry_t *registry        = muxserverGetDetachedRegistry(t, child_l);
    const size_t                   residual_charge = child_ls->pending_child_queue_charge;
    const size_t                   residual_count  = bufferqueueGetBufCount(&child_ls->pending_child_data);

    if (UNLIKELY((residual_charge == 0) != (residual_count == 0) || ! child_ls->detached_registered ||
                 child_ls->close_state != kMuxServerChildCloseParentGoneDraining || child_ls->parent != NULL ||
                 registry->count == 0 || registry->queued_charge < residual_charge))
    {
        LOGF("MuxServer: attempted to remove an absent or inconsistent detached child");
        abortProgramNow(1);
    }

    if (child_ls->detached_prev != NULL)
    {
        child_ls->detached_prev->detached_next = child_ls->detached_next;
    }
    else
    {
        if (UNLIKELY(registry->head != child_ls))
        {
            LOGF("MuxServer: detached registry head link is inconsistent");
            abortProgramNow(1);
        }
        registry->head = child_ls->detached_next;
    }
    if (child_ls->detached_next != NULL)
    {
        child_ls->detached_next->detached_prev = child_ls->detached_prev;
    }

    registry->queued_charge -= residual_charge;
    registry->count--;
    child_ls->pending_child_queue_charge = 0;
    child_ls->detached_prev              = NULL;
    child_ls->detached_next              = NULL;
    child_ls->detached_registered        = false;

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
    if (UNLIKELY((registry->count == 0) != (registry->head == NULL) ||
                 (registry->count == 0 && registry->queued_charge != 0)))
    {
        LOGF("MuxServer: detached registry count/head/charge invariant failed");
        abortProgramNow(1);
    }
}

muxserver_child_drain_result_t muxserverDrainDetachedChild(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls)
{
    assert(child_ls->close_state == kMuxServerChildCloseParentGoneDraining);
    assert(child_ls->parent == NULL);
    assert(child_ls->detached_registered);

    while (! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) > 0)
    {
        sbuf_t      *buf    = bufferqueuePopFront(&child_ls->pending_child_data);
        const size_t charge = sbufGetQueueCharge(buf);
        muxserverSubtractChildQueueCharge(child_ls, charge);
        muxserverSubtractDetachedCharge(t, child_l, charge);

        if (! lineCallWithRefWithBuf(child_l, tunnelNextUpStreamPayload, t, buf))
        {
            return kMuxServerChildDrainChildGone;
        }

        child_ls = lineGetState(child_l, t);
        if (UNLIKELY(child_ls->close_state != kMuxServerChildCloseParentGoneDraining || child_ls->parent != NULL ||
                     ! child_ls->detached_registered))
        {
            LOGF("MuxServer: detached child changed association while draining");
            abortProgramNow(1);
        }
    }

    return ! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) == 0
               ? kMuxServerChildDrainReadyToFinish
               : kMuxServerChildDrainBlocked;
}

void muxserverFinalizeDetachedChild(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls)
{
    assert(! child_ls->paused);
    assert(bufferqueueGetBufCount(&child_ls->pending_child_data) == 0);

    muxserverRemoveDetachedChild(t, child_l, child_ls);
    muxserverLinestateDestroy(t, child_ls);
    tunnelNextUpStreamFinish(t, child_l);
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }
}

void muxserverAbortDetachedChild(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls, bool notify_child_next)
{
    lineRef(child_l);
    muxserverRemoveDetachedChild(t, child_l, child_ls);
    muxserverLinestateDestroy(t, child_ls);
    if (notify_child_next)
    {
        tunnelNextUpStreamFinish(t, child_l);
    }
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }
    lineUnref(child_l);
}

bool muxserverFinalizeAttachedPeerClose(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                        muxserver_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    assert(child_ls->close_state == kMuxServerChildClosePeerDraining);
    assert(child_ls->parent == parent_ls);
    discard parent_ls;
    assert(! child_ls->paused);
    assert(bufferqueueGetBufCount(&child_ls->pending_child_data) == 0);

    lineRef(parent_l);
    muxserverLeaveConnection(child_ls);
    muxserverLinestateDestroy(t, child_ls);
    tunnelNextUpStreamFinish(t, child_l);
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }

    const bool parent_alive = lineIsAlive(parent_l);
    lineUnref(parent_l);
    return parent_alive;
}

bool muxserverBeginPeerCloseDrain(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts, muxserver_lstate_t *parent_ls,
                                  muxserver_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;
    discard ts;
    assert(child_ls->close_state == kMuxServerChildCloseOpen);

    const bool source_was_paused = muxserverChildSourcePaused(child_ls);
    child_ls->close_state        = kMuxServerChildClosePeerDraining;

    const muxserver_child_drain_result_t result =
        muxserverDrainAttachedChild(t, parent_l, parent_ls, child_l, child_ls);
    if (result == kMuxServerChildDrainChildGone || result == kMuxServerChildDrainParentGone)
    {
        return lineIsAlive(parent_l);
    }
    if (result == kMuxServerChildDrainReadyToFinish)
    {
        return muxserverFinalizeAttachedPeerClose(t, parent_l, parent_ls, child_ls);
    }

    if (! source_was_paused)
    {
        lineRef(parent_l);
        discard    lineCallWithRef(child_l, tunnelNextUpStreamPause, t);
        const bool parent_alive = lineIsAlive(parent_l);
        lineUnref(parent_l);
        return parent_alive;
    }
    return true;
}

static bool muxserverDetachedLimitReached(muxserver_tstate_t *ts, muxserver_detached_registry_t *registry)
{
    return (ts->detached_buffer_limit != kMuxDetachedLimitUnlimited &&
            registry->queued_charge >= (size_t) ts->detached_buffer_limit) ||
           (ts->detached_child_limit != kMuxDetachedLimitUnlimited && registry->count >= ts->detached_child_limit);
}

void muxserverHandleParentLoss(tunnel_t *t, line_t *parent_l, bool notify_parent_prev)
{
    muxserver_tstate_t *ts                = tunnelGetState(t);
    muxserver_lstate_t *parent_ls         = lineGetState(parent_l, t);
    uint32_t            detached_children = 0;
    size_t              detached_charge   = 0;

    /* A nested local failure cannot start another teardown. A real transport
     * Finish must still settle ownership immediately and suppress reflection. */
    if (parent_ls->parent_finishing && notify_parent_prev)
        return;

    assert(lineIsOnCurrentEventWorker(parent_l));
    lineRef(parent_l);
    parent_ls->parent_finishing = true;

    if (muxserverGetWorkerState(t, parent_l)->quiescing)
    {
        while (lineIsAlive(parent_l) && parent_ls->parent_state != NULL && parent_ls->child_next != NULL)
        {
            muxserverCloseChildKeepParent(t, parent_l, parent_ls, parent_ls->child_next, true);
            if (! lineIsAlive(parent_l) || parent_ls->parent_state == NULL)
            {
                lineUnref(parent_l);
                return;
            }
        }
        muxserverLinestateDestroy(t, parent_ls);
        if (notify_parent_prev)
        {
            tunnelPrevDownStreamFinish(t, parent_l);
        }
        lineUnref(parent_l);
        return;
    }

    while (lineIsAlive(parent_l) && parent_ls->parent_state != NULL && parent_ls->child_next != NULL)
    {
        muxserver_lstate_t *child_ls          = parent_ls->child_next;
        line_t             *child_l           = child_ls->l;
        const bool          source_was_paused = muxserverChildSourcePaused(child_ls);
        const size_t        queued_charge     = child_ls->pending_child_queue_charge;

        assert(child_ls->close_state == kMuxServerChildCloseOpen ||
               child_ls->close_state == kMuxServerChildClosePeerDraining);
        child_ls->close_state = kMuxServerChildCloseParentGoneDraining;
        muxserverSubtractParentPendingChildCharge(parent_ls, queued_charge);
        muxserverLeaveConnection(child_ls);
        muxserverRegisterDetachedChild(t, child_l, child_ls, queued_charge);
        detached_children++;
        if (UNLIKELY(detached_charge > SIZE_MAX - queued_charge))
        {
            LOGF("MuxServer: parent-loss diagnostic charge overflow");
            abortProgramNow(1);
        }
        detached_charge += queued_charge;

        const muxserver_child_drain_result_t result = muxserverDrainDetachedChild(t, child_l, child_ls);
        if (result == kMuxServerChildDrainChildGone)
        {
            continue;
        }
        if (result == kMuxServerChildDrainReadyToFinish)
        {
            muxserverFinalizeDetachedChild(t, child_l, child_ls);
            continue;
        }
        if (UNLIKELY(result != kMuxServerChildDrainBlocked))
        {
            LOGF("MuxServer: invalid detached drain result during parent loss");
            abortProgramNow(1);
        }

        child_ls                                = lineGetState(child_l, t);
        muxserver_detached_registry_t *registry = muxserverGetDetachedRegistry(t, child_l);
        if (muxserverDetachedLimitReached(ts, registry))
        {
            LOGW("MuxServer: aborting detached child cid %u at worker backlog limit "
                 "(child-retained-charge=%zu worker-children=%u worker-retained-charge=%zu "
                 "child-limit=%u charge-limit=%u)",
                 (unsigned int) child_ls->connection_id,
                 child_ls->pending_child_queue_charge,
                 registry->count,
                 registry->queued_charge,
                 ts->detached_child_limit,
                 ts->detached_buffer_limit);
            muxserverAbortDetachedChild(t, child_l, child_ls, true);
            continue;
        }

        if (! source_was_paused)
        {
            discard lineCallWithRef(child_l, tunnelNextUpStreamPause, t);
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
        LOGF("MuxServer: parent-loss transfer left attached child state behind");
        abortProgramNow(1);
    }

    LOGD("MuxServer: parent loss transferred detached-children=%u detached-retained-charge=%zu",
         detached_children,
         detached_charge);

    muxserverLinestateDestroy(t, parent_ls);
    if (notify_parent_prev)
    {
        tunnelPrevDownStreamFinish(t, parent_l);
    }
    lineUnref(parent_l);
}

/* A physical reference is held by each caller of this predicate. A borrowed
 * parent's local state can already be gone while its owner unwinds Finish. */
static bool muxserverParentOutputAlive(tunnel_t *t, line_t *parent_l)
{
    if (! lineIsAlive(parent_l))
        return false;
    muxserver_lstate_t *parent = lineGetState(parent_l, t);
    return parent->parent_state != NULL && ! parent->parent_finishing;
}

/* Snapshot physical references only on a gate transition. A callback may remove
 * any sibling or attach new children; Init/Est completion handles new arrivals. */
static void muxserverNotifyParentGate(tunnel_t *t, line_t *parent_l)
{
    muxserver_lstate_t  *parent = lineGetState(parent_l, t);
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
            LOGE("MuxServer: unable to snapshot children for parent write pressure");
            muxserverHandleParentLoss(t, parent_l, true);
            return;
        }
        size_t n = 0;
        for (muxserver_lstate_t *child = parent->child_next; child; child = child->child_next)
        {
            assert(n < count);
            children[n++] = child->l;
            lineRef(child->l);
        }
        for (size_t i = 0; i < n; ++i)
        {
            if (muxserverParentOutputAlive(t, parent_l) && output->sources_throttled == throttled &&
                lineIsAlive(children[i]))
            {
                muxserver_lstate_t *child = lineGetState(children[i], t);
                if (child->is_child && child->parent == parent && ! child->source_starting)
                {
                    if (throttled)
                        discard muxserverPauseChildSource(t, parent_l, child, false, true);
                    else
                        discard muxserverResumeChildSource(t, parent_l, child, false, true);
                }
            }
            lineUnref(children[i]);
        }
        memoryFree(children);
        if (! muxserverParentOutputAlive(t, parent_l))
            return;
        if (output->sources_throttled == throttled)
            break;
    }
    output->notifying = false;
}

void muxserverDrainParentOutput(tunnel_t *t, line_t *parent_l)
{
    muxserver_tstate_t *ts     = tunnelGetState(t);
    muxserver_lstate_t *parent = lineGetState(parent_l, t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing)
        return;
    mux_parent_output_t *output = &parent->parent_state->output;
    if (output->pumping)
        return;
    lineRef(parent_l);
    output->pumping = true;
    while (muxserverParentOutputAlive(t, parent_l) && ! output->transport_paused)
    {
        if (bufferqueueGetBufCount(&output->pending))
        {
            sbuf_t *buf = muxParentOutputPop(output);
            tunnelPrevDownStreamPayload(t, parent_l, buf);
            continue;
        }
        if (! output->sources_throttled || output->notifying)
            break;
        output->sources_throttled = false;
        muxserverNotifyParentGate(t, parent_l);
    }
    const bool alive = muxserverParentOutputAlive(t, parent_l);
    if (alive)
        output->pumping = false;
    lineUnref(parent_l);
}

bool muxserverSendParentOutput(tunnel_t *t, line_t *parent_l, sbuf_t *buf, muxserver_lstate_t *child, uint8_t flag)
{
    muxserver_tstate_t *ts     = tunnelGetState(t);
    muxserver_lstate_t *parent = lineGetState(parent_l, t);
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
            LOGE("MuxServer: parent write queue %s "
                 "(retained-charge=%zu candidate-charge=%zu limit=%u)",
                 reason,
                 output->charge,
                 candidate_charge,
                 ts->parent_write_limit);
            bufferpoolReuseBuffer(pool, buf);
            muxserverHandleParentLoss(t, parent_l, true);
            lineUnref(parent_l);
            return false;
        }
    }
    /* Admission and wire-state publication precede forwarding and gate fanout. */
    if (child != NULL)
    {
        if (flag == kMuxFlagFlowPause)
            child->flow_paused_sent = true;
        if (flag == kMuxFlagFlowResume)
            child->flow_paused_sent = false;
    }
    if (direct)
    {
        output->pumping = true;
        tunnelPrevDownStreamPayload(t, parent_l, buf);
        if (muxserverParentOutputAlive(t, parent_l))
            output->pumping = false;
    }
    else if (output->charge >= ts->parent_write_pause_threshold && ! output->sources_throttled)
    {
        output->sources_throttled = true;
        muxserverNotifyParentGate(t, parent_l);
    }
    if (muxserverParentOutputAlive(t, parent_l))
        muxserverDrainParentOutput(t, parent_l);
    const bool alive = muxserverParentOutputAlive(t, parent_l);
    lineUnref(parent_l);
    return alive;
}

void muxserverSendSpliceBatch(tunnel_t *t, line_t *parent_l, sbuf_t *input, muxserver_lstate_t *child)
{
    muxserver_tstate_t  *ts     = tunnelGetState(t);
    muxserver_lstate_t  *parent = lineGetState(parent_l, t);
    mux_parent_output_t *output = &parent->parent_state->output;
    lineRef(parent_l);
    if (! muxEncodeSpliceBatch(
            lineGetBufferPool(parent_l), input, child->connection_id, false, output, ts->parent_write_limit))
    {
        LOGE("MuxServer: complete splice batch exceeds parent limit or reservation failed");
        muxserverHandleParentLoss(t, parent_l, true);
        lineUnref(parent_l);
        return;
    }
    /* Complete parent ownership precedes gate callbacks. */
    if (output->charge >= ts->parent_write_pause_threshold && ! output->sources_throttled)
    {
        output->sources_throttled = true;
        muxserverNotifyParentGate(t, parent_l);
    }
    if (muxserverParentOutputAlive(t, parent_l))
        muxserverDrainParentOutput(t, parent_l);
    lineUnref(parent_l);
}
