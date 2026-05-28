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


void muxserverMakeMuxFrame(sbuf_t *buf, cid_t cid, uint8_t flag)
{
    if (sbufGetLength(buf) > 0xFFFF - kMuxFrameLength)
    {
        LOGF("MuxServer: Buffer length exceeds maximum allowed size for MUX frame: %zu", sbufGetLength(buf));
        terminateProgram(1);
    }

    mux_frame_t frame = {.length = sbufGetLength(buf),
                         .cid    = cid, // will be set later
                         .flags  = flag,
                         ._pad1  = 0};
    frame.length = htobe16(frame.length);
    frame.cid    = htobe32(frame.cid);
    sbufShiftLeft(buf, kMuxFrameLength);
    sbufWrite(buf, &frame, kMuxFrameLength);
}

static size_t muxserverChildResumeThreshold(muxserver_tstate_t *ts)
{
    return min((size_t) kMuxChildBufferResumeThreshold, (size_t) ts->child_buffer_limit);
}

static bool muxserverAnyChildBufferAtLimit(muxserver_tstate_t *ts, muxserver_lstate_t *parent_ls)
{
    muxserver_lstate_t *child_ls = parent_ls->child_next;
    while (child_ls)
    {
        if (bufferqueueGetBufLen(&child_ls->pending_child_data) >= ts->child_buffer_limit)
        {
            return true;
        }
        child_ls = child_ls->child_next;
    }
    return false;
}

bool muxserverSendControlFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                               cid_t cid, uint8_t flag)
{
    if (parent_ls->parent_finishing)
    {
        return true;
    }

    sbuf_t *control_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(parent_l));
    muxserverMakeMuxFrame(control_buf, cid, flag);

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
                                      muxserver_lstate_t *parent_ls, line_t *child_l,
                                      muxserver_lstate_t *child_ls)
{
    if (parent_ls->parent_finishing || child_ls->flow_paused_sent)
    {
        return true;
    }

    if (bufferqueueGetBufLen(&child_ls->pending_child_data) < ts->child_buffer_pause_tolerance)
    {
        return true;
    }

    child_ls->flow_paused_sent = true;
    return muxserverSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowPause);
}

static bool muxserverMaybePauseParentForChildBuffers(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                                     muxserver_lstate_t *parent_ls)
{
    if (parent_ls->parent_finishing || parent_ls->parent_input_paused ||
        ! muxserverAnyChildBufferAtLimit(ts, parent_ls))
    {
        return true;
    }

    lineLock(parent_l);
    parent_ls->parent_input_paused = true;
    tunnelPrevDownStreamPause(t, parent_l);
    if (! lineIsAlive(parent_l))
    {
        lineUnlock(parent_l);
        return false;
    }
    lineUnlock(parent_l);
    return true;
}

bool muxserverMaybeResumeParentForChildBuffers(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                               muxserver_lstate_t *parent_ls)
{
    if (! parent_ls->parent_input_paused || parent_ls->parent_finishing ||
        muxserverAnyChildBufferAtLimit(ts, parent_ls))
    {
        return true;
    }

    lineLock(parent_l);
    parent_ls->parent_input_paused = false;
    tunnelPrevDownStreamResume(t, parent_l);
    if (! lineIsAlive(parent_l))
    {
        lineUnlock(parent_l);
        return false;
    }
    lineUnlock(parent_l);
    return true;
}

bool muxserverQueueChildPayload(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                muxserver_lstate_t *parent_ls, muxserver_lstate_t *child_ls, sbuf_t *buf)
{
    bufferqueuePushBack(&child_ls->pending_child_data, buf);
    if (! muxserverMaybeSendChildFlowPause(t, parent_l, ts, parent_ls, child_ls->l, child_ls))
    {
        return false;
    }
    return muxserverMaybePauseParentForChildBuffers(t, parent_l, ts, parent_ls);
}

static bool muxserverHandleChildBufferAfterDrain(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                                 muxserver_lstate_t *parent_ls, line_t *child_l,
                                                 muxserver_lstate_t *child_ls)
{
    size_t pending_bytes = bufferqueueGetBufLen(&child_ls->pending_child_data);

    if (pending_bytes < ts->child_buffer_limit &&
        ! muxserverMaybeResumeParentForChildBuffers(t, parent_l, ts, parent_ls))
    {
        return false;
    }

    if (! child_ls->paused && child_ls->flow_paused_sent && pending_bytes < muxserverChildResumeThreshold(ts))
    {
        child_ls->flow_paused_sent = false;
        if (! muxserverSendControlFrame(t, parent_l, parent_ls, child_l, child_ls->connection_id,
                                        kMuxFlagFlowResume))
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
            if (! muxserverMaybeResumeParentForChildBuffers(t, parent_l, ts, parent_ls))
            {
                lineUnlock(parent_l);
                return false;
            }
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
