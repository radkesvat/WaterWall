#include "structure.h"

#include "loggers/network_logger.h"


void muxserverTunnelUpStreamFinish(tunnel_t *t, line_t *parent_l)
{
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

    muxserver_lstate_t *child_ls = parent_ls->child_next;
    while (child_ls)
    {
        muxserver_lstate_t *temp = child_ls->child_next;
        line_t* child_l = child_ls->l;
        muxserverLeaveConnection(child_ls);
        muxserverLinestateDestroy(child_ls);
        tunnelNextUpStreamFinish(t, child_l);
        lineDestroy(child_l);
        child_ls = temp;
    }

    muxserverLinestateDestroy(parent_ls);
}


