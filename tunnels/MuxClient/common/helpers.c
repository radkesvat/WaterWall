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
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    if (! ts->log_main_line_stats || parent_ls->is_child)
    {
        return;
    }

    muxclient_parent_stats_t stats;
    muxclientCollectParentStats(parent_ls, &stats);

    LOGI("MuxClient: main line stats wid=%u parent-line-write-paused=%s parent-line-read-paused=no "
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
        const line_task_submit_result_e result =
            lineScheduleDelayedTask(parent_l, muxclientParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t, NULL);
        discard result;
    }
}

void muxclientScheduleParentStatsLog(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t *ts = tunnelGetState(t);

    if (! ts->log_main_line_stats)
    {
        return;
    }

    /* Optional statistics sampling is intentionally lossy under pressure. */
    const line_task_submit_result_e result =
        lineScheduleDelayedTask(parent_l, muxclientParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t, NULL);
    discard result;
}

static bool muxclientCreateParentLine(tunnel_t *t, wid_t wid, line_t **selection_slot)
{
    line_t             *parent_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    muxclientLinestateInitialize(parent_ls, parent_l, false, 0);
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
    muxclientLinestateDestroy(parent_ls);
    tunnelNextUpStreamFinish(t, parent_l);

    if (lineIsAlive(parent_l))
    {
        lineDestroy(parent_l);
    }
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

void muxclientCloseChildKeepParent(tunnel_t *t, muxclient_tstate_t *ts, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                   muxclient_lstate_t *child_ls, bool notify_child_prev)
{
    line_t         *child_l     = child_ls->l;
    const mux_cid_t cid         = child_ls->connection_id;
    const bool      open_sent   = child_ls->open_frame_sent;
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
        if (parent_alive && ! parent_ls->parent_finishing && muxclientParentShouldCloseWhenIdle(ts, parent_ls) &&
            parent_ls->children_count == 0)
        {
            muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent_ls);
        }
        return;
    }

    sbuf_t *finishpacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    if (open_sent)
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

    if (! lineCallWithRefWithBuf(parent_l, tunnelNextUpStreamPayload, t, finishpacket_buf))
    {
        return;
    }

    if (muxclientParentShouldCloseWhenIdle(ts, parent_ls) && parent_ls->children_count == 0)
    {
        muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent_ls);
    }
}

static void muxclientAddParentPendingChildBytes(muxclient_lstate_t *parent_ls, size_t bytes)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    if (UNLIKELY(parent_ls->pending_child_data_len > SIZE_MAX - bytes))
    {
        LOGF("MuxClient: parent queued-byte accounting overflow");
        abortProgramNow(1);
    }

    parent_ls->pending_child_data_len += bytes;
}

static void muxclientSubtractParentPendingChildBytes(muxclient_lstate_t *parent_ls, size_t bytes)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    if (UNLIKELY(parent_ls->pending_child_data_len < bytes))
    {
        LOGF("MuxClient: parent queued-byte accounting underflow");
        abortProgramNow(1);
    }

    parent_ls->pending_child_data_len -= bytes;
}

static void muxclientReleaseChildPendingBytes(muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    size_t pending_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);
    if (pending_bytes == 0)
    {
        return;
    }

    muxclientSubtractParentPendingChildBytes(parent_ls, pending_bytes);
}

bool muxclientSendControlFrame(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                               mux_cid_t cid, uint8_t flag)
{
    if (parent_ls->parent_finishing)
    {
        return true;
    }

    sbuf_t *control_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(parent_l));
    muxMakeMuxFrame(control_buf, cid, flag);

    lineRef(child_l);
    lineRef(parent_l);
    parent_ls->last_writer = child_l;
    tunnelNextUpStreamPayload(t, parent_l, control_buf);
    if (! lineIsAlive(parent_l))
    {
        lineUnref(parent_l);
        lineUnref(child_l);
        return false;
    }
    parent_ls->last_writer = NULL;
    const bool child_alive = lineIsAlive(child_l);
    lineUnref(parent_l);
    lineUnref(child_l);
    return child_alive;
}

bool muxclientMaybeSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                      muxclient_lstate_t *parent_ls, line_t *child_l, muxclient_lstate_t *child_ls)
{
    if (bufferqueueGetBufLen(&child_ls->pending_child_data) < ts->child_buffer_pause_tolerance)
    {
        return true;
    }

    return muxclientSendChildFlowPause(t, parent_l, parent_ls, child_l, child_ls);
}

bool muxclientSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                                 muxclient_lstate_t *child_ls)
{
    if (parent_ls->parent_finishing || child_ls->close_state != kMuxClientChildCloseOpen || child_ls->flow_paused_sent)
    {
        return true;
    }

    child_ls->flow_paused_sent = true;
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
    discard t;

    muxclientReleaseChildPendingBytes(parent_ls, child_ls);
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
                                             const char *reason)
{
    line_t         *child_l             = child_ls->l;
    const mux_cid_t cid                 = child_ls->connection_id;
    const size_t    child_queued_bytes  = bufferqueueGetBufLen(&child_ls->pending_child_data);
    const size_t    parent_queued_bytes = parent_ls->pending_child_data_len;

    if (child_ls->close_state == kMuxClientChildCloseOpen &&
        ! muxclientSendControlFrame(t, parent_l, parent_ls, child_l, cid, kMuxFlagClose))
    {
        return false;
    }

    LOGW("MuxClient: closing child cid %u because %s (child-queued-bytes=%zu parent-queued-bytes=%zu)",
         (unsigned int) cid,
         reason,
         child_queued_bytes,
         parent_queued_bytes);

    muxclientLeaveConnection(child_ls);
    bool parent_alive = muxclientReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);
    muxclientLinestateDestroy(child_ls);
    tunnelPrevDownStreamFinish(t, child_l);
    if (! parent_alive || ! lineIsAlive(parent_l))
    {
        return false;
    }

    if (muxclientParentShouldCloseWhenIdle(ts, parent_ls) && parent_ls->children_count == 0)
    {
        muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent_ls);
        return false;
    }

    return true;
}

/*
 * Return the actual largest queued child. Children remain in ownership-list
 * insertion order; replacing on an equal size makes the stable tie-break prefer
 * the oldest attached child.
 */
static muxclient_lstate_t *muxclientFindLargestQueuedChild(muxclient_lstate_t *parent_ls, size_t *queued_bytes_out)
{
    muxclient_lstate_t *largest      = NULL;
    size_t              largest_size = 0;

    for (muxclient_lstate_t *child_ls = parent_ls->child_next; child_ls != NULL; child_ls = child_ls->child_next)
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
static bool muxclientShedForParentBufferLimit(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                              muxclient_lstate_t *parent_ls)
{
    if (ts->parent_buffer_limit == kMuxParentBufferLimitUnlimited ||
        parent_ls->pending_child_data_len < (size_t) ts->parent_buffer_limit)
    {
        return true;
    }

    const size_t        total_before_close = parent_ls->pending_child_data_len;
    size_t              victim_bytes       = 0;
    muxclient_lstate_t *victim             = muxclientFindLargestQueuedChild(parent_ls, &victim_bytes);

    if (UNLIKELY(victim == NULL || victim_bytes == 0 || victim_bytes > total_before_close))
    {
        LOGE("MuxClient: parent queue accounting is inconsistent: %zu bytes accounted across %u children, "
             "largest child queue is %zu bytes",
             total_before_close,
             parent_ls->children_count,
             victim_bytes);
        return true;
    }

    if (! muxclientCloseChildForQueueLimit(
            t, parent_l, ts, parent_ls, victim, "queued child data on the parent reached its limit"))
    {
        return false;
    }

    if (UNLIKELY(parent_ls->pending_child_data_len >= (size_t) ts->parent_buffer_limit))
    {
        LOGE("MuxClient: parent queue remained over limit after closing its largest child: "
             "%zu bytes remain, limit is %u",
             parent_ls->pending_child_data_len,
             ts->parent_buffer_limit);
    }

    return true;
}

bool muxclientQueueChildPayload(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls,
                                muxclient_lstate_t *child_ls, sbuf_t *buf)
{
    assert(child_ls->close_state == kMuxClientChildCloseOpen);
    assert(child_ls->parent == parent_ls);

    size_t buf_len = sbufGetLength(buf);

    bufferqueuePushBack(&child_ls->pending_child_data, buf);
    muxclientAddParentPendingChildBytes(parent_ls, buf_len);

    if (bufferqueueGetBufLen(&child_ls->pending_child_data) >= ts->child_buffer_limit)
    {
        return muxclientCloseChildForQueueLimit(
            t, parent_l, ts, parent_ls, child_ls, "its own queued child data reached its limit");
    }

    if (! muxclientMaybeSendChildFlowPause(t, parent_l, ts, parent_ls, child_ls->l, child_ls))
    {
        return false;
    }

    return muxclientShedForParentBufferLimit(t, parent_l, ts, parent_ls);
}

static bool muxclientHandleChildBufferAfterDrain(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                                 muxclient_lstate_t *parent_ls, line_t *child_l,
                                                 muxclient_lstate_t *child_ls)
{
    size_t pending_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);

    if (child_ls->close_state == kMuxClientChildCloseOpen && ! child_ls->paused && child_ls->flow_paused_sent &&
        pending_bytes < ts->child_buffer_resume_threshold)
    {
        child_ls->flow_paused_sent = false;
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
        sbuf_t *buf = bufferqueuePopFront(&child_ls->pending_child_data);
        muxclientSubtractParentPendingChildBytes(parent_ls, sbufGetLength(buf));
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

static void muxclientRegisterDetachedChild(muxclient_tstate_t *ts, line_t *child_l, size_t queued_bytes)
{
    const wid_t wid = lineGetWID(child_l);
    assert(lineIsOnCurrentEventWorker(child_l));
    assert(workerWIDIsRegistered(wid));

    if (UNLIKELY(ts->detached_child_counts == NULL || ts->detached_queued_bytes == NULL || wid >= ts->workers_count ||
                 ts->detached_child_counts[wid] == UINT32_MAX ||
                 ts->detached_queued_bytes[wid] > SIZE_MAX - queued_bytes))
    {
        LOGF("MuxClient: detached child accounting overflow on worker %d", (int) wid);
        abortProgramNow(1);
    }

    ts->detached_child_counts[wid]++;
    ts->detached_queued_bytes[wid] += queued_bytes;
}

static void muxclientSubtractDetachedBytes(muxclient_tstate_t *ts, line_t *child_l, size_t bytes)
{
    const wid_t wid = lineGetWID(child_l);
    assert(lineIsOnCurrentEventWorker(child_l));

    if (UNLIKELY(ts->detached_queued_bytes == NULL || wid >= ts->workers_count ||
                 ts->detached_queued_bytes[wid] < bytes))
    {
        LOGF("MuxClient: detached byte accounting underflow on worker %d", (int) wid);
        abortProgramNow(1);
    }
    ts->detached_queued_bytes[wid] -= bytes;
}

static void muxclientRemoveDetachedChild(muxclient_tstate_t *ts, line_t *child_l, muxclient_lstate_t *child_ls)
{
    const wid_t  wid            = lineGetWID(child_l);
    const size_t residual_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);

    assert(lineIsOnCurrentEventWorker(child_l));
    assert(child_ls->close_state == kMuxClientChildCloseParentGoneDraining);
    assert(child_ls->parent == NULL);

    if (UNLIKELY(ts->detached_child_counts == NULL || ts->detached_queued_bytes == NULL || wid >= ts->workers_count ||
                 ts->detached_child_counts[wid] == 0 || ts->detached_queued_bytes[wid] < residual_bytes))
    {
        LOGF("MuxClient: invalid detached child removal on worker %d", (int) wid);
        abortProgramNow(1);
    }

    ts->detached_queued_bytes[wid] -= residual_bytes;
    ts->detached_child_counts[wid]--;
}

muxclient_child_drain_result_t muxclientDrainDetachedChild(tunnel_t *t, line_t *child_l, muxclient_lstate_t *child_ls)
{
    muxclient_tstate_t *ts = tunnelGetState(t);

    assert(lineIsOnCurrentEventWorker(child_l));
    assert(child_ls->close_state == kMuxClientChildCloseParentGoneDraining);
    assert(child_ls->parent == NULL);

    while (! child_ls->paused && bufferqueueGetBufCount(&child_ls->pending_child_data) > 0)
    {
        sbuf_t      *buf     = bufferqueuePopFront(&child_ls->pending_child_data);
        const size_t buf_len = sbufGetLength(buf);
        muxclientSubtractDetachedBytes(ts, child_l, buf_len);

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
    if (parent_ls->last_writer == child_l)
    {
        parent_ls->last_writer = NULL;
    }
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
    if (parent_ls->last_writer == child_l)
    {
        parent_ls->last_writer = NULL;
    }

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
            ts->detached_queued_bytes[wid] >= (size_t) ts->detached_buffer_limit) ||
           (ts->detached_child_limit != kMuxDetachedLimitUnlimited &&
            ts->detached_child_counts[wid] >= ts->detached_child_limit);
}

void muxclientHandleParentLoss(tunnel_t *t, line_t *parent_l, bool notify_parent_next)
{
    muxclient_tstate_t *ts                = tunnelGetState(t);
    muxclient_lstate_t *parent_ls         = lineGetState(parent_l, t);
    const wid_t         wid               = lineGetWID(parent_l);
    uint32_t            detached_children = 0;
    size_t              detached_bytes    = 0;

    assert(lineIsOnCurrentEventWorker(parent_l));
    muxclientForgetParentSelection(ts, wid, parent_l);

    lineRef(parent_l);
    parent_ls->parent_finishing = true;

    while (parent_ls->child_next != NULL)
    {
        muxclient_lstate_t *child_ls          = parent_ls->child_next;
        line_t             *child_l           = child_ls->l;
        const bool          source_was_paused = muxclientChildSourcePaused(child_ls);
        const size_t        queued_bytes      = bufferqueueGetBufLen(&child_ls->pending_child_data);

        assert(child_ls->close_state == kMuxClientChildCloseOpen ||
               child_ls->close_state == kMuxClientChildClosePeerDraining);
        child_ls->close_state = kMuxClientChildCloseParentGoneDraining;
        if (parent_ls->last_writer == child_l)
        {
            parent_ls->last_writer = NULL;
        }
        muxclientSubtractParentPendingChildBytes(parent_ls, queued_bytes);
        muxclientLeaveConnection(child_ls);
        muxclientRegisterDetachedChild(ts, child_l, queued_bytes);
        detached_children++;
        detached_bytes += queued_bytes;

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
                 "(child-residual-bytes=%zu worker-children=%u worker-residual-bytes=%zu "
                 "child-limit=%u byte-limit=%u)",
                 (unsigned int) child_ls->connection_id,
                 bufferqueueGetBufLen(&child_ls->pending_child_data),
                 ts->detached_child_counts[wid],
                 ts->detached_queued_bytes[wid],
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

    if (UNLIKELY(parent_ls->children_count != 0 || parent_ls->child_next != NULL ||
                 parent_ls->pending_child_data_len != 0))
    {
        LOGF("MuxClient: parent-loss transfer left attached child state behind");
        abortProgramNow(1);
    }

    LOGD("MuxClient: parent loss transferred detached-children=%u detached-queued-bytes=%zu",
         detached_children,
         detached_bytes);

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
