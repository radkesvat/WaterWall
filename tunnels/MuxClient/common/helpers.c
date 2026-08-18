#include "structure.h"

#include "loggers/network_logger.h"

void muxclientJoinConnection(muxclient_lstate_t *parent, muxclient_lstate_t *child)
{
    assert(child != NULL && parent != NULL && child->is_child && (parent->is_child == false));
    child->parent   = parent;
    child->is_child = true;

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
    if (child == NULL || ! child->is_child || child->parent == NULL)
    {
        return;
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

    child->parent->children_count--;

    child->parent     = NULL;
    child->child_prev = NULL;
    child->child_next = NULL;
    child->is_child   = false;
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

    LOGI("MuxClient: main line stats wid=%u parent-line-write-paused=%s parent-queued-bytes=%zu "
         "children-count=%u childs-read-paused=%u childs-write-paused=%u",
         (unsigned int) lineGetWID(parent_l),
         boolToYesNo(stats.parent_write_paused > 0),
         parent_ls->pending_child_data_len,
         parent_ls->children_count,
         stats.child_read_paused,
         stats.child_write_paused);

    if (! parent_ls->parent_finishing)
    {
        /* Optional statistics sampling is intentionally lossy under pressure. */
        discard lineScheduleDelayedTask(parent_l, muxclientParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t);
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
    discard lineScheduleDelayedTask(parent_l, muxclientParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t);
}

static bool muxclientCreateParentLine(tunnel_t *t, wid_t wid, line_t **selection_slot)
{
    line_t             *parent_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    muxclientLinestateInitialize(parent_ls, parent_l, false, 0);
    assert(*selection_slot == NULL);
    *selection_slot = parent_l;

    if (! withLineLocked(parent_l, tunnelNextUpStreamInit, t))
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
                ts->unsatisfied_lines[wid] = NULL;
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
    line_t         *child_l   = child_ls->l;
    const mux_cid_t cid       = child_ls->connection_id;
    const bool      open_sent = child_ls->open_frame_sent;

    muxclientLeaveConnection(child_ls);

    const bool parent_alive = muxclientReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);

    if (! parent_alive || parent_ls->parent_finishing)
    {
        // no Close frame can be written; the peer learns about the close from the dying parent connection
        muxclientLinestateDestroy(child_ls);
        if (notify_child_prev)
        {
            tunnelPrevDownStreamFinish(t, child_l);
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

    if (! withLineLockedWithBuf(parent_l, tunnelNextUpStreamPayload, t, finishpacket_buf))
    {
        return;
    }

    if (muxclientCheckConnectionIsExhausted(ts, parent_ls) && parent_ls->children_count == 0)
    {
        muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent_ls);
    }
}

static size_t muxclientChildResumeThreshold(muxclient_tstate_t *ts)
{
    return min((size_t) kMuxChildBufferResumeThreshold, (size_t) ts->child_buffer_limit);
}

static void muxclientAddParentPendingChildBytes(muxclient_lstate_t *parent_ls, size_t bytes)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    assert(parent_ls->pending_child_data_len <= SIZE_MAX - bytes);

    parent_ls->pending_child_data_len += bytes;
}

static void muxclientSubtractParentPendingChildBytes(muxclient_lstate_t *parent_ls, size_t bytes)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    assert(parent_ls->pending_child_data_len >= bytes);

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

    lineLock(parent_l);
    parent_ls->last_writer = child_l;
    tunnelNextUpStreamPayload(t, parent_l, control_buf);
    if (! lineIsAlive(parent_l))
    {
        lineUnlock(parent_l);
        return false;
    }
    parent_ls->last_writer = NULL;
    lineUnlock(parent_l);
    return true;
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
    if (parent_ls->parent_finishing || child_ls->flow_paused_sent)
    {
        return true;
    }

    child_ls->flow_paused_sent = true;
    return muxclientSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowPause);
}

/*
 * Queue pressure never pauses reads on the parent transport.
 *
 * The parent is shared by every child stream, so a pause taken on behalf of one child can
 * only be cleared by that same child draining its queue. A child whose downstream peer has
 * stopped reading never drains, and while the parent is paused no frame - not the peer's
 * FlowPause acknowledgement, not another child's reply - can be read from it, so nothing
 * that could clear the pause is able to arrive. One stalled stream therefore deadlocks every
 * stream multiplexed onto the same parent until the stalled peer moves or the connection
 * times out.
 *
 * Pressure is relieved by shedding instead: `child-buffer-limit` closes a single runaway
 * child, and `parent-buffer-limit` closes the largest queues until the parent total is back
 * under its ceiling. Both always terminate, because each close frees the queue that caused it.
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
    return child_ls->peer_flow_paused || child_ls->parent_write_paused;
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
    line_t   *child_l = child_ls->l;
    mux_cid_t cid     = child_ls->connection_id;

    if (! muxclientSendControlFrame(t, parent_l, parent_ls, child_l, cid, kMuxFlagClose))
    {
        // the parent died mid-write, so the child is not being closed for its queue after all
        return false;
    }

    LOGW("MuxClient: closing child cid %u because %s (%zu bytes queued on the parent)",
         (unsigned int) cid,
         reason,
         parent_ls->pending_child_data_len);

    muxclientLeaveConnection(child_ls);
    bool parent_alive = muxclientReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);
    muxclientLinestateDestroy(child_ls);
    tunnelPrevDownStreamFinish(t, child_l);
    if (! parent_alive || ! lineIsAlive(parent_l))
    {
        return false;
    }

    if (muxclientCheckConnectionIsExhausted(ts, parent_ls) && parent_ls->children_count == 0)
    {
        muxclientCloseIdleExhaustedParentLine(t, ts, lineGetWID(parent_l), parent_l, parent_ls);
        return false;
    }

    return true;
}

/*
 * Sheds the children holding the most queued data until the parent total is back under
 * `parent-buffer-limit`.
 *
 * One pass over the child list, so the work is bounded by the child count even though a
 * parent may carry tens of thousands of children: this runs inside a payload callback and
 * must not turn one queued frame into an unbounded amount of work. The cut is the mean queue
 * length at entry - the total being at or over the limit guarantees at least one child sits
 * at or above it, so a pass always sheds something and always makes progress. A pass that
 * does not get all the way under the ceiling is simply re-entered by the next queued payload.
 *
 * The result describes the parent, not the shed children: false means the parent line is gone
 * and the caller must stop using it.
 */
static bool muxclientShedForParentBufferLimit(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                              muxclient_lstate_t *parent_ls)
{
    if (ts->parent_buffer_limit == kMuxParentBufferLimitUnlimited ||
        parent_ls->pending_child_data_len < (size_t) ts->parent_buffer_limit)
    {
        return true;
    }

    const size_t children = (parent_ls->children_count > 0) ? (size_t) parent_ls->children_count : (size_t) 1;
    size_t       cut      = parent_ls->pending_child_data_len / children;
    if (cut == 0)
    {
        cut = 1;
    }

    uint32_t            shed_count = 0;
    muxclient_lstate_t *child_ls   = parent_ls->child_next;

    while (child_ls != NULL && parent_ls->pending_child_data_len >= (size_t) ts->parent_buffer_limit)
    {
        muxclient_lstate_t *next = child_ls->child_next;

        if (bufferqueueGetBufLen(&child_ls->pending_child_data) >= cut)
        {
            shed_count++;
            if (! muxclientCloseChildForQueueLimit(
                    t, parent_l, ts, parent_ls, child_ls, "queued child data on the parent reached limit"))
            {
                return false;
            }
        }

        child_ls = next;
    }

    if (shed_count == 0)
    {
        // Nothing was over the cut while the total was over the limit, so the accounted total
        // no longer matches the queues behind it. Left silent this would shed a healthy child
        // on every subsequent payload and never recover, so say so instead.
        LOGE("MuxClient: parent queue accounting is inconsistent: %zu bytes accounted across %u children with none "
             "at or above the %zu byte cut",
             parent_ls->pending_child_data_len,
             parent_ls->children_count,
             cut);
    }

    return true;
}

bool muxclientQueueChildPayload(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls,
                                muxclient_lstate_t *child_ls, sbuf_t *buf)
{
    size_t buf_len = sbufGetLength(buf);

    bufferqueuePushBack(&child_ls->pending_child_data, buf);
    muxclientAddParentPendingChildBytes(parent_ls, buf_len);

    if (bufferqueueGetBufLen(&child_ls->pending_child_data) >= ts->child_buffer_limit)
    {
        return muxclientCloseChildForQueueLimit(
            t, parent_l, ts, parent_ls, child_ls, "its own queued child data reached limit");
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

    if (! child_ls->paused && child_ls->flow_paused_sent && pending_bytes < muxclientChildResumeThreshold(ts))
    {
        child_ls->flow_paused_sent = false;
        if (! muxclientSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowResume))
        {
            return false;
        }
    }

    return true;
}

bool muxclientFlushChildPending(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                                muxclient_lstate_t *child_ls, bool fin_mode)
{
    muxclient_tstate_t *ts = tunnelGetState(t);

    lineLock(parent_l);
    while (bufferqueueGetBufCount(&child_ls->pending_child_data) > 0)
    {
        if (child_ls->paused && ! fin_mode)
        {
            break;
        }

        sbuf_t *buf = bufferqueuePopFront(&child_ls->pending_child_data);
        muxclientSubtractParentPendingChildBytes(parent_ls, sbufGetLength(buf));
        if (! withLineLockedWithBuf(child_l, tunnelPrevDownStreamPayload, t, buf))
        {
            lineUnlock(parent_l);
            return false;
        }

        if (! lineIsAlive(parent_l))
        {
            lineUnlock(parent_l);
            return false;
        }

        if (fin_mode)
        {
            continue;
        }

        if (child_ls->paused)
        {
            break;
        }

        if (! muxclientHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
        {
            lineUnlock(parent_l);
            return false;
        }
    }

    if (! fin_mode && ! child_ls->paused &&
        ! muxclientHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
    {
        lineUnlock(parent_l);
        return false;
    }

    lineUnlock(parent_l);
    return true;
}
