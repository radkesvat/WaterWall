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

    if (ls->connection_id == CID_MAX)
    {
        LOGE("MuxClient: Connection exhausted, connection id reached maximum value: %u", CID_MAX);
        return true;
    }

    if (ls->children_count == CID_MAX)
    {
        LOGE("MuxClient: Connection exhausted, children count reached maximum value: %u", CID_MAX);
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

void muxclientForgetParentLine(muxclient_tstate_t *ts, wid_t wid, line_t *parent_l)
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

static const char *muxclientBoolText(bool value)
{
    return value ? "yes" : "no";
}

static void muxclientCollectParentStats(muxclient_lstate_t *parent_ls, muxclient_parent_stats_t *stats)
{
    memorySet(stats, 0, sizeof(*stats));

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

    LOGI("MuxClient: main line stats wid=%u parent-line-write-paused=%s parent-line-read-paused=%s "
         "children-count=%u childs-read-paused=%u childs-write-paused=%u",
         (unsigned int) lineGetWID(parent_l), muxclientBoolText(stats.parent_write_paused > 0),
         muxclientBoolText(parent_ls->parent_read_pause_count > 0), parent_ls->children_count,
         stats.child_read_paused, stats.child_write_paused);

    if (! parent_ls->parent_finishing)
    {
        lineScheduleDelayedTask(parent_l, muxclientParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t);
    }
}

void muxclientScheduleParentStatsLog(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t *ts = tunnelGetState(t);

    if (! ts->log_main_line_stats)
    {
        return;
    }

    lineScheduleDelayedTask(parent_l, muxclientParentStatsLogTask, kMuxMainLineStatsLogIntervalMs, t);
}

static bool muxclientCreateParentLine(tunnel_t *t, wid_t wid, line_t **parent_l_out)
{
    line_t             *parent_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, t);

    muxclientLinestateInitialize(parent_ls, parent_l, false, 0);

    if (! withLineLocked(parent_l, tunnelNextUpStreamInit, t))
    {
        *parent_l_out = NULL;
        return false;
    }

    muxclientScheduleParentStatsLog(t, parent_l);
    *parent_l_out = parent_l;
    return true;
}

static void muxclientCloseIdleExhaustedParentLine(tunnel_t *t, muxclient_tstate_t *ts, wid_t wid, line_t *parent_l,
                                                  muxclient_lstate_t *parent_ls)
{
    assert(parent_ls->is_child == false);
    assert(parent_ls->children_count == 0);

    muxclientForgetParentLine(ts, wid, parent_l);
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

        line_t *parent_l = NULL;
        if (! muxclientCreateParentLine(t, wid, &parent_l))
        {
            return NULL;
        }
        *slot = parent_l;
    }

    uint32_t start_index = ts->fixed_next_parent_indexes[wid] % ts->fixed_connections_count;
    uint32_t best_index  = start_index;
    uint32_t best_count  = UINT32_MAX;
    bool     found       = false;

    for (uint32_t i = 0; i < ts->fixed_connections_count; ++i)
    {
        uint32_t idx = (start_index + i) % ts->fixed_connections_count;
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
        line_t *parent_l = NULL;
        if (! muxclientCreateParentLine(t, wid, &parent_l))
        {
            return NULL;
        }

        ts->unsatisfied_lines[wid] = parent_l;
    }

    return ts->unsatisfied_lines[wid];
}

static void muxclientSetMuxFrameHeader(mux_frame_t *frame, mux_length_t length, cid_t cid, uint8_t flag)
{
    *frame = (mux_frame_t) {.length = htobe16(length), .flags = flag, ._pad1 = 0, .cid = htobe32(cid)};
}

static void muxclientCheckPayloadFrameLength(uint32_t payload_length)
{
    if (payload_length > 0xFFFF - kMuxFrameLength)
    {
        LOGF("MuxClient: Buffer length exceeds maximum allowed size for MUX frame: %u", payload_length);
        terminateProgram(1);
    }
}

void muxclientMakeMuxFrame(sbuf_t *buf, cid_t cid, uint8_t flag)
{
    muxclientCheckPayloadFrameLength(sbufGetLength(buf));

    mux_frame_t frame;
    muxclientSetMuxFrameHeader(&frame, (mux_length_t) sbufGetLength(buf), cid, flag);
    sbufShiftLeft(buf, kMuxFrameLength);
    sbufWrite(buf, &frame, kMuxFrameLength);
}

void muxclientMakeMuxOpenDataFrames(sbuf_t *buf, cid_t cid)
{
    uint32_t payload_length = sbufGetLength(buf);
    muxclientCheckPayloadFrameLength(payload_length);

    mux_frame_t open_frame;
    mux_frame_t data_frame;
    muxclientSetMuxFrameHeader(&open_frame, 0, cid, kMuxFlagOpen);
    muxclientSetMuxFrameHeader(&data_frame, (mux_length_t) payload_length, cid, kMuxFlagData);

    sbufShiftLeft(buf, kMuxFrameLength * 2);
    sbufWrite(buf, &open_frame, kMuxFrameLength);
    memoryCopy(sbufGetMutablePtr(buf) + kMuxFrameLength, &data_frame, kMuxFrameLength);
}

void muxclientMakeMuxOpenCloseFrames(sbuf_t *buf, cid_t cid)
{
    mux_frame_t open_frame;
    mux_frame_t close_frame;
    muxclientSetMuxFrameHeader(&open_frame, 0, cid, kMuxFlagOpen);
    muxclientSetMuxFrameHeader(&close_frame, 0, cid, kMuxFlagClose);

    sbufShiftLeft(buf, kMuxFrameLength * 2);
    sbufWrite(buf, &open_frame, kMuxFrameLength);
    memoryCopy(sbufGetMutablePtr(buf) + kMuxFrameLength, &close_frame, kMuxFrameLength);
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
                               cid_t cid, uint8_t flag)
{
    if (parent_ls->parent_finishing)
    {
        return true;
    }

    sbuf_t *control_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(parent_l));
    muxclientMakeMuxFrame(control_buf, cid, flag);

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
                                      muxclient_lstate_t *parent_ls, line_t *child_l,
                                      muxclient_lstate_t *child_ls)
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

bool muxclientMaybePauseParentInputForChild(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                            muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls)
{
    if (parent_ls->parent_finishing || child_ls->parent_read_paused)
    {
        return true;
    }

    if (bufferqueueGetBufLen(&child_ls->pending_child_data) < ts->child_buffer_pause_tolerance)
    {
        return true;
    }

    child_ls->parent_read_paused = true;
    parent_ls->parent_read_pause_count++;

    return withLineLocked(parent_l, tunnelNextUpStreamPause, t);
}

static bool muxclientMaybePauseParentInputForAggregate(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                                       muxclient_lstate_t *parent_ls)
{
    if (parent_ls->parent_finishing || parent_ls->aggregate_read_paused)
    {
        return true;
    }

    if (parent_ls->pending_child_data_len < ts->child_buffer_pause_tolerance)
    {
        return true;
    }

    parent_ls->aggregate_read_paused = true;
    parent_ls->parent_read_pause_count++;

    return withLineLocked(parent_l, tunnelNextUpStreamPause, t);
}

bool muxclientResumeParentInputForChild(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                        muxclient_lstate_t *child_ls)
{
    if (! child_ls->parent_read_paused)
    {
        return true;
    }

    assert(parent_ls->parent_read_pause_count > 0);

    child_ls->parent_read_paused = false;
    parent_ls->parent_read_pause_count--;

    if (parent_ls->parent_read_pause_count > 0 || parent_ls->parent_finishing)
    {
        return true;
    }

    return withLineLocked(parent_l, tunnelNextUpStreamResume, t);
}

static bool muxclientResumeParentInputForAggregate(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                                   muxclient_lstate_t *parent_ls)
{
    if (! parent_ls->aggregate_read_paused)
    {
        return true;
    }

    if (parent_ls->pending_child_data_len >= muxclientChildResumeThreshold(ts))
    {
        return true;
    }

    assert(parent_ls->parent_read_pause_count > 0);

    parent_ls->aggregate_read_paused = false;
    parent_ls->parent_read_pause_count--;

    if (parent_ls->parent_read_pause_count > 0 || parent_ls->parent_finishing)
    {
        return true;
    }

    return withLineLocked(parent_l, tunnelNextUpStreamResume, t);
}

bool muxclientReleaseParentInputForChildClose(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                              muxclient_lstate_t *child_ls)
{
    muxclient_tstate_t *ts = tunnelGetState(t);

    muxclientReleaseChildPendingBytes(parent_ls, child_ls);

    if (! muxclientResumeParentInputForChild(t, parent_l, parent_ls, child_ls))
    {
        return false;
    }

    return muxclientResumeParentInputForAggregate(t, parent_l, ts, parent_ls);
}

static bool muxclientChildSourcePaused(muxclient_lstate_t *child_ls)
{
    return child_ls->peer_flow_paused || child_ls->parent_write_paused;
}

bool muxclientPauseChildSource(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *child_ls, bool peer_flow,
                               bool parent_write)
{
    line_t *child_l      = child_ls->l;
    bool    was_paused   = muxclientChildSourcePaused(child_ls);

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

static bool muxclientCloseChildForBufferLimit(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                              muxclient_lstate_t *parent_ls,
                                              muxclient_lstate_t *child_ls)
{
    line_t *child_l = child_ls->l;
    cid_t   cid     = child_ls->connection_id;

    LOGW("MuxClient: closing child cid %u because queued child data reached limit", cid);

    if (! muxclientSendControlFrame(t, parent_l, parent_ls, child_l, cid, kMuxFlagClose))
    {
        return false;
    }

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

bool muxclientQueueChildPayload(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls, sbuf_t *buf)
{
    size_t buf_len = sbufGetLength(buf);

    bufferqueuePushBack(&child_ls->pending_child_data, buf);
    muxclientAddParentPendingChildBytes(parent_ls, buf_len);

    if (bufferqueueGetBufLen(&child_ls->pending_child_data) >= ts->child_buffer_limit)
    {
        return muxclientCloseChildForBufferLimit(t, parent_l, ts, parent_ls, child_ls);
    }

    if (! muxclientMaybeSendChildFlowPause(t, parent_l, ts, parent_ls, child_ls->l, child_ls))
    {
        return false;
    }

    if (! muxclientMaybePauseParentInputForChild(t, parent_l, ts, parent_ls, child_ls))
    {
        return false;
    }
    if (! muxclientMaybePauseParentInputForAggregate(t, parent_l, ts, parent_ls))
    {
        return false;
    }
    return true;
}

static bool muxclientHandleChildBufferAfterDrain(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                                 muxclient_lstate_t *parent_ls, line_t *child_l,
                                                 muxclient_lstate_t *child_ls)
{
    size_t pending_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);

    if (! child_ls->paused && child_ls->flow_paused_sent && pending_bytes < muxclientChildResumeThreshold(ts))
    {
        child_ls->flow_paused_sent = false;
        if (! muxclientSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id,
                                        kMuxFlagFlowResume))
        {
            return false;
        }
    }

    if (! child_ls->paused && pending_bytes < muxclientChildResumeThreshold(ts))
    {
        if (! muxclientResumeParentInputForChild(t, parent_l, parent_ls, child_ls))
        {
            return false;
        }
    }

    return muxclientResumeParentInputForAggregate(t, parent_l, ts, parent_ls);
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
