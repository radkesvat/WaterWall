#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDownStreamFinish(tunnel_t *t, line_t *child_l)
{
    muxserver_lstate_t *child_ls = lineGetState(child_l, t);
    assert(child_ls->is_child);

    if (! child_ls->parent)
    {
        muxserverLinestateDestroy(child_ls);
        return;
    }

    muxserver_lstate_t *parent_ls = child_ls->parent;
    line_t             *parent_l  = parent_ls->l;
    muxserverLeaveConnection(child_ls);

    if (parent_ls->paused)
    {
        parent_ls->paused = false;

        sbuf_t *resumepacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
        muxserverMakeMuxFrame(resumepacket_buf, child_ls->connection_id, kMuxFlagFlowResume);

        lineLock(parent_l);
        tunnelPrevDownStreamPayload(t, parent_l, resumepacket_buf);
        if (! lineIsAlive(parent_l))
        {
            muxserverLinestateDestroy(child_ls);
            lineUnlock(parent_l);
            return;
        }
        tunnelPrevDownStreamResume(t, parent_l);
        if (! lineIsAlive(parent_l))
        {
            muxserverLinestateDestroy(child_ls);
            lineUnlock(parent_l);
            return;
        }
        lineUnlock(parent_l);
    }

    sbuf_t *finishpacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    muxserverMakeMuxFrame(finishpacket_buf, child_ls->connection_id, kMuxFlagClose);
    muxserverLinestateDestroy(child_ls);
    tunnelPrevDownStreamPayload(t, parent_l, finishpacket_buf);
}
