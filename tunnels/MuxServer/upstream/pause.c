#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelUpStreamPause(tunnel_t *t, line_t *parent_l)
{

    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

    if (LIKELY(parent_ls->last_writer != NULL))
    {
        line_t *rl             = parent_ls->last_writer;
        parent_ls->last_writer = NULL;
        tunnelNextUpStreamPause(t, rl);
    }
    else
    {
        muxserver_lstate_t *child_ls = parent_ls->child_next;
        lineLock(parent_l);
        while (child_ls && lineIsAlive(parent_l))
        {
            muxserver_lstate_t *temp = child_ls->child_next;
            tunnelNextUpStreamPause(t, child_ls->l);
            child_ls = temp;
        }
        lineUnlock(parent_l);
    }
}
