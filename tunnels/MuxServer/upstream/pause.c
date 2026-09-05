#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelUpStreamPause(tunnel_t *t, line_t *parent_l)
{
    muxserver_tstate_t *ts_shutdown = tunnelGetState(t);
    if (ts_shutdown->worker_states[lineGetWID(parent_l)].quiescing)
    {
        return;
    }

    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);

    if (parent_ls->parent_finishing)
    {
        return;
    }

    if (LIKELY(parent_ls->last_writer != NULL))
    {
        line_t             *rl       = parent_ls->last_writer;
        muxserver_lstate_t *child_ls = lineGetState(rl, t);
        parent_ls->last_writer       = NULL;
        lineRef(parent_l);
        discard muxserverPauseChildSource(t, parent_l, child_ls, false, true);
        lineUnref(parent_l);
    }
    else
    {
        muxserver_lstate_t *child_ls = parent_ls->child_next;
        lineRef(parent_l);
        while (child_ls && lineIsAlive(parent_l))
        {
            muxserver_lstate_t *temp = child_ls->child_next;
            if (! muxserverPauseChildSource(t, parent_l, child_ls, false, true))
            {
                break;
            }
            child_ls = temp;
        }
        lineUnref(parent_l);
    }
}
