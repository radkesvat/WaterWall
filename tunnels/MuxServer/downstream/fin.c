#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDownStreamFinish(tunnel_t *t, line_t *child_l)
{
    muxserver_lstate_t *child_ls = lineGetState(child_l, t);
    assert(child_ls->is_child);

    assert(child_ls->parent);

    muxserver_lstate_t *parent_ls = child_ls->parent;
    line_t             *parent_l  = parent_ls->l;
    cid_t               cid       = child_ls->connection_id;
    muxserverLeaveConnection(child_ls);

    if (parent_ls->parent_finishing)
    {
        muxserverLinestateDestroy(child_ls);
        lineDestroy(child_l);
        return;
    }

    if (! muxserverResumeParentInputForChild(t, parent_l, parent_ls, child_ls))
    {
        muxserverLinestateDestroy(child_ls);
        lineDestroy(child_l);
        return;
    }

    sbuf_t *finishpacket_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(child_l));
    muxserverMakeMuxFrame(finishpacket_buf, cid, kMuxFlagClose);
    muxserverLinestateDestroy(child_ls);
    lineDestroy(child_l);
    tunnelPrevDownStreamPayload(t, parent_l, finishpacket_buf);
}
