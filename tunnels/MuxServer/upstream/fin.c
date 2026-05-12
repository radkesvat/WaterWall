#include "structure.h"

#include "loggers/network_logger.h"

static void muxserverCloseOwnedChildLineFromUpstreamFinish(tunnel_t *t, line_t *child_l, muxserver_lstate_t *child_ls)
{
    lineLock(child_l);

    muxserverLeaveConnection(child_ls);
    muxserverLinestateDestroy(child_ls);
    tunnelNextUpStreamFinish(t, child_l);

    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }

    lineUnlock(child_l);
}

void muxserverTunnelUpStreamFinish(tunnel_t *t, line_t *parent_l)
{
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

    lineLock(parent_l);
    parent_ls->parent_finishing = true;

    muxserver_lstate_t *child_ls = parent_ls->child_next;
    while (child_ls)
    {
        muxserver_lstate_t *temp    = child_ls->child_next;
        line_t             *child_l = child_ls->l;

        if (muxserverFlushChildPending(t, parent_l, parent_ls, child_l, child_ls, true))
        {
            muxserverCloseOwnedChildLineFromUpstreamFinish(t, child_l, child_ls);
        }

        if (! lineIsAlive(parent_l))
        {
            lineUnlock(parent_l);
            return;
        }

        child_ls = temp;
    }

    muxserverLinestateDestroy(parent_ls);
    lineUnlock(parent_l);
}
