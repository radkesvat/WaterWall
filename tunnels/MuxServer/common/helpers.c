#include "structure.h"

#include "loggers/network_logger.h"

void muxserverJoinConnection(muxserver_lstate_t *parent, muxserver_lstate_t *child)
{
    assert(child != NULL && parent != NULL && child->is_child && (parent->is_child == false));
    if (UNLIKELY(parent->children_count == UINT32_MAX))
    {
        LOGF("MuxServer: parent child-count overflow");
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
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

    if (! ts->log_main_line_stats || parent_ls->is_child)
    {
        return;
    }

    muxserver_parent_stats_t stats;
    muxserverCollectParentStats(parent_ls, &stats);

    LOGI("MuxServer: main line stats wid=%u parent-line-write-paused=%s parent-line-read-paused=no "
         "children-count=%u children-close-pending=%u childs-read-paused=%u childs-write-paused=%u "
         "parent-queued-bytes=%zu",
         (unsigned int) lineGetWID(parent_l),
         boolToYesNo(stats.parent_write_paused > 0),
         parent_ls->children_count,
         stats.children_close_pending,
         stats.child_read_paused,
         stats.child_write_paused,
         parent_ls->pending_child_data_len);

    if (! parent_ls->parent_finishing)
    {
        /* Optional statistics sampling is intentionally lossy under pressure. */
        discard lineScheduleDelayedTask(parent_l, muxserverParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t);
    }
}

void muxserverScheduleParentStatsLog(tunnel_t *t, line_t *parent_l)
{
    muxserver_tstate_t *ts = tunnelGetState(t);

    if (! ts->log_main_line_stats)
    {
        return;
    }

    /* Optional statistics sampling is intentionally lossy under pressure. */
    discard lineScheduleDelayedTask(parent_l, muxserverParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t);
}

void muxserverCloseChildKeepParent(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                   muxserver_lstate_t *child_ls, bool notify_child_next)
{
    line_t         *child_l     = child_ls->l;
    const mux_cid_t cid         = child_ls->connection_id;
    const bool      notify_peer = child_ls->close_state == kMuxServerChildCloseOpen;

    muxserverLeaveConnection(child_ls);

    const bool parent_alive = muxserverReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);

    if (! parent_alive || parent_ls->parent_finishing || ! notify_peer)
    {
        // no Close frame can be written; the peer learns about the close from the dying parent connection
        muxserverLinestateDestroy(child_ls);
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

    sbuf_t *finishpacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    muxMakeMuxFrame(finishpacket_buf, cid, kMuxFlagClose);

    muxserverLinestateDestroy(child_ls);

    if (notify_child_next)
    {
        tunnelNextUpStreamFinish(t, child_l);
    }

    // MuxServer created this child line, so MuxServer destroys it
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }

    tunnelPrevDownStreamPayload(t, parent_l, finishpacket_buf);
}

static void muxserverAddParentPendingChildBytes(muxserver_lstate_t *parent_ls, size_t bytes)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    if (UNLIKELY(parent_ls->pending_child_data_len > SIZE_MAX - bytes))
    {
        LOGF("MuxServer: parent queued-byte accounting overflow");
        abortProgramNow(1);
    }

    parent_ls->pending_child_data_len += bytes;
}

static void muxserverSubtractParentPendingChildBytes(muxserver_lstate_t *parent_ls, size_t bytes)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    if (UNLIKELY(parent_ls->pending_child_data_len < bytes))
    {
        LOGF("MuxServer: parent queued-byte accounting underflow");
        abortProgramNow(1);
    }

    parent_ls->pending_child_data_len -= bytes;
}

static void muxserverReleaseChildPendingBytes(muxserver_lstate_t *parent_ls, muxserver_lstate_t *child_ls)
{
    size_t pending_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);
    if (pending_bytes == 0)
    {
        return;
    }

    muxserverSubtractParentPendingChildBytes(parent_ls, pending_bytes);
}

bool muxserverSendControlFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                               mux_cid_t cid, uint8_t flag)
{
    if (parent_ls->parent_finishing)
    {
        return true;
    }

    sbuf_t *control_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(parent_l));
    muxMakeMuxFrame(control_buf, cid, flag);

    lineLock(child_l);
    lineLock(parent_l);
    parent_ls->last_writer = child_l;
    tunnelPrevDownStreamPayload(t, parent_l, control_buf);
    if (! lineIsAlive(parent_l))
    {
        lineUnlock(parent_l);
        lineUnlock(child_l);
        return false;
    }
    parent_ls->last_writer = NULL;
    const bool child_alive = lineIsAlive(child_l);
    lineUnlock(parent_l);
    lineUnlock(child_l);
    return child_alive;
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

    child_ls->flow_paused_sent = true;
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
    discard t;

    muxserverReleaseChildPendingBytes(parent_ls, child_ls);
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
                                             muxserver_lstate_t *child_ls, const char *reason)
{
    line_t         *child_l             = child_ls->l;
    const mux_cid_t cid                 = child_ls->connection_id;
    const size_t    child_queued_bytes  = bufferqueueGetBufLen(&child_ls->pending_child_data);
    const size_t    parent_queued_bytes = parent_ls->pending_child_data_len;

    if (child_ls->close_state == kMuxServerChildCloseOpen &&
        ! muxserverSendControlFrame(t, parent_l, parent_ls, child_l, cid, kMuxFlagClose))
    {
        return false;
    }

    LOGW("MuxServer: closing child cid %u because %s (child-queued-bytes=%zu parent-queued-bytes=%zu)",
         (unsigned int) cid,
         reason,
         child_queued_bytes,
         parent_queued_bytes);

    muxserverLeaveConnection(child_ls);
    bool parent_alive = muxserverReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);
    muxserverLinestateDestroy(child_ls);
    tunnelNextUpStreamFinish(t, child_l);
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }
    return parent_alive && lineIsAlive(parent_l);
}

/*
 * Return the actual largest queued child. Children are kept in most-recently-used
 * order by the frame parser; replacing on an equal size therefore makes the stable
 * tie-break prefer the least-recently-active child.
 */
static muxserver_lstate_t *muxserverFindLargestQueuedChild(muxserver_lstate_t *parent_ls, size_t *queued_bytes_out)
{
    muxserver_lstate_t *largest      = NULL;
    size_t              largest_size = 0;

    for (muxserver_lstate_t *child_ls = parent_ls->child_next; child_ls != NULL; child_ls = child_ls->child_next)
    {
        const size_t queued = bufferqueueGetBufLen(&child_ls->pending_child_data);
        if (queued > 0 && queued >= largest_size)
        {
            largest      = child_ls;
            largest_size = queued;
        }
    }

    *queued_bytes_out = largest_size;
    return largest;
}

/*
 * The parent total was below its budget before the payload currently being queued.
 * If that payload has length B, its destination now holds at least B queued bytes,
 * so the largest child queue is at least B. Removing that one queue leaves no more
 * than the old, below-budget total. One O(children) scan and one close are therefore
 * sufficient in the normal path; no average-based heuristic or repeated scan is
 * needed.
 */
static bool muxserverShedForParentBufferLimit(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                              muxserver_lstate_t *parent_ls)
{
    if (ts->parent_buffer_limit == kMuxParentBufferLimitUnlimited ||
        parent_ls->pending_child_data_len < (size_t) ts->parent_buffer_limit)
    {
        return true;
    }

    const size_t        total_before_close = parent_ls->pending_child_data_len;
    size_t              victim_bytes       = 0;
    muxserver_lstate_t *victim             = muxserverFindLargestQueuedChild(parent_ls, &victim_bytes);

    if (UNLIKELY(victim == NULL || victim_bytes == 0 || victim_bytes > total_before_close))
    {
        LOGE("MuxServer: parent queue accounting is inconsistent: %zu bytes accounted across %u children, "
             "largest child queue is %zu bytes",
             total_before_close,
             parent_ls->children_count,
             victim_bytes);
        return true;
    }

    if (! muxserverCloseChildForQueueLimit(
            t, parent_l, parent_ls, victim, "queued child data on the parent reached its limit"))
    {
        return false;
    }

    if (UNLIKELY(parent_ls->pending_child_data_len >= (size_t) ts->parent_buffer_limit))
    {
        LOGE("MuxServer: parent queue remained over limit after closing its largest child: "
             "%zu bytes remain, limit is %u",
             parent_ls->pending_child_data_len,
             ts->parent_buffer_limit);
    }

    return true;
}

bool muxserverQueueChildPayload(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts, muxserver_lstate_t *parent_ls,
                                muxserver_lstate_t *child_ls, sbuf_t *buf)
{
    assert(child_ls->close_state == kMuxServerChildCloseOpen);
    assert(child_ls->parent == parent_ls);

    size_t buf_len = sbufGetLength(buf);

    bufferqueuePushBack(&child_ls->pending_child_data, buf);
    muxserverAddParentPendingChildBytes(parent_ls, buf_len);

    if (bufferqueueGetBufLen(&child_ls->pending_child_data) >= ts->child_buffer_limit)
    {
        return muxserverCloseChildForQueueLimit(
            t, parent_l, parent_ls, child_ls, "its own queued child data reached its limit");
    }

    if (! muxserverMaybeSendChildFlowPause(t, parent_l, ts, parent_ls, child_ls->l, child_ls))
    {
        return false;
    }

    return muxserverShedForParentBufferLimit(t, parent_l, ts, parent_ls);
}

static bool muxserverHandleChildBufferAfterDrain(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                                 muxserver_lstate_t *parent_ls, line_t *child_l,
                                                 muxserver_lstate_t *child_ls)
{
    size_t pending_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);

    if (child_ls->close_state == kMuxServerChildCloseOpen && ! child_ls->paused && child_ls->flow_paused_sent &&
        pending_bytes < ts->child_buffer_resume_threshold)
    {
        child_ls->flow_paused_sent = false;
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

    lineLock(parent_l);
    while (! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&child_ls->pending_child_data);
        muxserverSubtractParentPendingChildBytes(parent_ls, sbufGetLength(buf));
        if (! withLineLockedWithBuf(child_l, tunnelNextUpStreamPayload, t, buf))
        {
            lineUnlock(parent_l);
            return kMuxServerChildDrainChildGone;
        }

        if (! lineIsAlive(parent_l))
        {
            lineUnlock(parent_l);
            return kMuxServerChildDrainParentGone;
        }

        child_ls = lineGetState(child_l, t);
        if (child_ls->close_state == kMuxServerChildCloseParentGoneDraining || child_ls->parent != parent_ls)
        {
            lineUnlock(parent_l);
            return kMuxServerChildDrainParentGone;
        }

        if (child_ls->paused)
        {
            break;
        }

        if (! muxserverHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
        {
            lineUnlock(parent_l);
            return kMuxServerChildDrainParentGone;
        }
    }

    if (! child_ls->paused && ! muxserverHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
    {
        lineUnlock(parent_l);
        return kMuxServerChildDrainParentGone;
    }

    const muxserver_child_drain_result_t result =
        ! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) == 0
            ? kMuxServerChildDrainReadyToFinish
            : kMuxServerChildDrainBlocked;
    lineUnlock(parent_l);
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
    return &ts->detached_registries[wid];
}

static void muxserverRegisterDetachedChild(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls,
                                           size_t queued_bytes)
{
    muxserver_detached_registry_t *registry = muxserverGetDetachedRegistry(t, child_l);

    assert(child_ls->parent == NULL);
    assert(child_ls->close_state == kMuxServerChildCloseParentGoneDraining);
    if (UNLIKELY(child_ls->detached_registered || child_ls->detached_prev != NULL || child_ls->detached_next != NULL ||
                 registry->count == UINT32_MAX || registry->queued_bytes > SIZE_MAX - queued_bytes))
    {
        LOGF("MuxServer: duplicate detached registration or accounting overflow");
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
    registry->queued_bytes += queued_bytes;
}

static void muxserverSubtractDetachedBytes(tunnel_t *t, line_t *child_l, size_t bytes)
{
    muxserver_detached_registry_t *registry = muxserverGetDetachedRegistry(t, child_l);
    if (UNLIKELY(registry->queued_bytes < bytes))
    {
        LOGF("MuxServer: detached byte accounting underflow");
        abortProgramNow(1);
    }
    registry->queued_bytes -= bytes;
}

static void muxserverRemoveDetachedChild(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls)
{
    muxserver_detached_registry_t *registry       = muxserverGetDetachedRegistry(t, child_l);
    const size_t                   residual_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);

    if (UNLIKELY(! child_ls->detached_registered || child_ls->close_state != kMuxServerChildCloseParentGoneDraining ||
                 child_ls->parent != NULL || registry->count == 0 || registry->queued_bytes < residual_bytes))
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

    registry->queued_bytes -= residual_bytes;
    registry->count--;
    child_ls->detached_prev       = NULL;
    child_ls->detached_next       = NULL;
    child_ls->detached_registered = false;

    if (UNLIKELY((registry->count == 0) != (registry->head == NULL) ||
                 (registry->count == 0 && registry->queued_bytes != 0)))
    {
        LOGF("MuxServer: detached registry count/head/byte invariant failed");
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
        sbuf_t      *buf     = bufferqueuePopFront(&child_ls->pending_child_data);
        const size_t buf_len = sbufGetLength(buf);
        muxserverSubtractDetachedBytes(t, child_l, buf_len);

        if (! withLineLockedWithBuf(child_l, tunnelNextUpStreamPayload, t, buf))
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
    muxserverLinestateDestroy(child_ls);
    tunnelNextUpStreamFinish(t, child_l);
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }
}

void muxserverAbortDetachedChild(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls, bool notify_child_next)
{
    muxserverRemoveDetachedChild(t, child_l, child_ls);
    muxserverLinestateDestroy(child_ls);
    if (notify_child_next)
    {
        tunnelNextUpStreamFinish(t, child_l);
    }
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }
}

bool muxserverFinalizeAttachedPeerClose(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                        muxserver_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;

    assert(child_ls->close_state == kMuxServerChildClosePeerDraining);
    assert(child_ls->parent == parent_ls);
    assert(! child_ls->paused);
    assert(bufferqueueGetBufCount(&child_ls->pending_child_data) == 0);

    lineLock(parent_l);
    if (parent_ls->last_writer == child_l)
    {
        parent_ls->last_writer = NULL;
    }
    muxserverLeaveConnection(child_ls);
    muxserverLinestateDestroy(child_ls);
    tunnelNextUpStreamFinish(t, child_l);
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }

    const bool parent_alive = lineIsAlive(parent_l);
    lineUnlock(parent_l);
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
    if (parent_ls->last_writer == child_l)
    {
        parent_ls->last_writer = NULL;
    }

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
        lineLock(parent_l);
        discard    withLineLocked(child_l, tunnelNextUpStreamPause, t);
        const bool parent_alive = lineIsAlive(parent_l);
        lineUnlock(parent_l);
        return parent_alive;
    }
    return true;
}

static bool muxserverDetachedLimitReached(muxserver_tstate_t *ts, muxserver_detached_registry_t *registry)
{
    return (ts->detached_buffer_limit != kMuxDetachedLimitUnlimited &&
            registry->queued_bytes >= (size_t) ts->detached_buffer_limit) ||
           (ts->detached_child_limit != kMuxDetachedLimitUnlimited && registry->count >= ts->detached_child_limit);
}

void muxserverHandleParentLoss(tunnel_t *t, line_t *parent_l, bool notify_parent_prev)
{
    muxserver_tstate_t *ts                = tunnelGetState(t);
    muxserver_lstate_t *parent_ls         = lineGetState(parent_l, t);
    uint32_t            detached_children = 0;
    size_t              detached_bytes    = 0;

    assert(lineIsOnCurrentEventWorker(parent_l));
    lineLock(parent_l);
    parent_ls->parent_finishing = true;

    while (parent_ls->child_next != NULL)
    {
        muxserver_lstate_t *child_ls          = parent_ls->child_next;
        line_t             *child_l           = child_ls->l;
        const bool          source_was_paused = muxserverChildSourcePaused(child_ls);
        const size_t        queued_bytes      = bufferqueueGetBufLen(&child_ls->pending_child_data);

        assert(child_ls->close_state == kMuxServerChildCloseOpen ||
               child_ls->close_state == kMuxServerChildClosePeerDraining);
        child_ls->close_state = kMuxServerChildCloseParentGoneDraining;
        if (parent_ls->last_writer == child_l)
        {
            parent_ls->last_writer = NULL;
        }
        muxserverSubtractParentPendingChildBytes(parent_ls, queued_bytes);
        muxserverLeaveConnection(child_ls);
        muxserverRegisterDetachedChild(t, child_l, child_ls, queued_bytes);
        detached_children++;
        detached_bytes += queued_bytes;

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
                 "(child-residual-bytes=%zu worker-children=%u worker-residual-bytes=%zu "
                 "child-limit=%u byte-limit=%u)",
                 (unsigned int) child_ls->connection_id,
                 bufferqueueGetBufLen(&child_ls->pending_child_data),
                 registry->count,
                 registry->queued_bytes,
                 ts->detached_child_limit,
                 ts->detached_buffer_limit);
            muxserverAbortDetachedChild(t, child_l, child_ls, true);
            continue;
        }

        if (! source_was_paused)
        {
            discard withLineLocked(child_l, tunnelNextUpStreamPause, t);
        }
    }

    if (UNLIKELY(parent_ls->children_count != 0 || parent_ls->child_next != NULL ||
                 parent_ls->pending_child_data_len != 0))
    {
        LOGF("MuxServer: parent-loss transfer left attached child state behind");
        abortProgramNow(1);
    }

    LOGD("MuxServer: parent loss transferred detached-children=%u detached-queued-bytes=%zu",
         detached_children,
         detached_bytes);

    muxserverLinestateDestroy(parent_ls);
    if (notify_parent_prev)
    {
        tunnelPrevDownStreamFinish(t, parent_l);
    }
    lineUnlock(parent_l);
}
