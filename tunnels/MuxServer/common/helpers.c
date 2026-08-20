#include "structure.h"

#include "loggers/network_logger.h"

void muxserverJoinConnection(muxserver_lstate_t *parent, muxserver_lstate_t *child)
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

    child->parent->children_count--;

    child->parent     = NULL;
    child->child_prev = NULL;
    child->child_next = NULL;
    child->is_child   = false;
}

typedef struct muxserver_parent_stats_s
{
    uint32_t parent_write_paused;
    uint32_t child_read_paused;
    uint32_t child_write_paused;
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

    LOGI("MuxServer: main line stats wid=%u parent-line-write-paused=%s parent-queued-bytes=%zu "
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
    line_t         *child_l = child_ls->l;
    const mux_cid_t cid     = child_ls->connection_id;

    muxserverLeaveConnection(child_ls);

    const bool parent_alive = muxserverReleaseParentInputForChildClose(t, parent_l, parent_ls, child_ls);

    if (! parent_alive || parent_ls->parent_finishing)
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

static size_t muxserverChildResumeThreshold(muxserver_tstate_t *ts)
{
    return min((size_t) kMuxChildBufferResumeThreshold, (size_t) ts->child_buffer_limit);
}

static void muxserverAddParentPendingChildBytes(muxserver_lstate_t *parent_ls, size_t bytes)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    assert(parent_ls->pending_child_data_len <= SIZE_MAX - bytes);

    parent_ls->pending_child_data_len += bytes;
}

static void muxserverSubtractParentPendingChildBytes(muxserver_lstate_t *parent_ls, size_t bytes)
{
    assert(parent_ls != NULL && ! parent_ls->is_child);
    assert(parent_ls->pending_child_data_len >= bytes);

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

    lineLock(parent_l);
    parent_ls->last_writer = child_l;
    tunnelPrevDownStreamPayload(t, parent_l, control_buf);
    if (! lineIsAlive(parent_l))
    {
        lineUnlock(parent_l);
        return false;
    }
    parent_ls->last_writer = NULL;
    lineUnlock(parent_l);
    return true;
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
    if (parent_ls->parent_finishing || child_ls->flow_paused_sent)
    {
        return true;
    }

    child_ls->flow_paused_sent = true;
    return muxserverSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowPause);
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
bool muxserverReleaseParentInputForChildClose(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                              muxserver_lstate_t *child_ls)
{
    discard t;

    muxserverReleaseChildPendingBytes(parent_ls, child_ls);

    return lineIsAlive(parent_l);
}

static bool muxserverChildSourcePaused(muxserver_lstate_t *child_ls)
{
    return child_ls->peer_flow_paused || child_ls->parent_write_paused;
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
    line_t   *child_l = child_ls->l;
    mux_cid_t cid     = child_ls->connection_id;

    if (! muxserverSendControlFrame(t, parent_l, parent_ls, child_l, cid, kMuxFlagClose))
    {
        // the parent died mid-write, so the child is not being closed for its queue after all
        return false;
    }

    LOGW("MuxServer: closing child cid %u because %s (%zu bytes queued on the parent)",
         (unsigned int) cid,
         reason,
         parent_ls->pending_child_data_len);

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
static bool muxserverShedForParentBufferLimit(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                              muxserver_lstate_t *parent_ls)
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
    muxserver_lstate_t *child_ls   = parent_ls->child_next;

    while (child_ls != NULL && parent_ls->pending_child_data_len >= (size_t) ts->parent_buffer_limit)
    {
        muxserver_lstate_t *next = child_ls->child_next;

        if (bufferqueueGetBufLen(&child_ls->pending_child_data) >= cut)
        {
            shed_count++;
            if (! muxserverCloseChildForQueueLimit(
                    t, parent_l, parent_ls, child_ls, "queued child data on the parent reached limit"))
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
        LOGE("MuxServer: parent queue accounting is inconsistent: %zu bytes accounted across %u children with none "
             "at or above the %zu byte cut",
             parent_ls->pending_child_data_len,
             parent_ls->children_count,
             cut);
    }

    return true;
}

bool muxserverQueueChildPayload(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts, muxserver_lstate_t *parent_ls,
                                muxserver_lstate_t *child_ls, sbuf_t *buf)
{
    size_t buf_len = sbufGetLength(buf);

    bufferqueuePushBack(&child_ls->pending_child_data, buf);
    muxserverAddParentPendingChildBytes(parent_ls, buf_len);

    if (bufferqueueGetBufLen(&child_ls->pending_child_data) >= ts->child_buffer_limit)
    {
        return muxserverCloseChildForQueueLimit(
            t, parent_l, parent_ls, child_ls, "its own queued child data reached limit");
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

    if (! child_ls->paused && child_ls->flow_paused_sent && pending_bytes < muxserverChildResumeThreshold(ts))
    {
        child_ls->flow_paused_sent = false;
        if (! muxserverSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowResume))
        {
            return false;
        }
    }

    return true;
}

bool muxserverFlushChildPending(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                                muxserver_lstate_t *child_ls, bool fin_mode)
{
    muxserver_tstate_t *ts = tunnelGetState(t);

    lineLock(parent_l);
    while (bufferqueueGetBufCount(&child_ls->pending_child_data) > 0)
    {
        if (child_ls->paused && ! fin_mode)
        {
            break;
        }

        sbuf_t *buf = bufferqueuePopFront(&child_ls->pending_child_data);
        muxserverSubtractParentPendingChildBytes(parent_ls, sbufGetLength(buf));
        if (! withLineLockedWithBuf(child_l, tunnelNextUpStreamPayload, t, buf))
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

        if (! muxserverHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
        {
            lineUnlock(parent_l);
            return false;
        }
    }

    if (! fin_mode && ! child_ls->paused &&
        ! muxserverHandleChildBufferAfterDrain(t, parent_l, ts, parent_ls, child_l, child_ls))
    {
        lineUnlock(parent_l);
        return false;
    }

    lineUnlock(parent_l);
    return true;
}
