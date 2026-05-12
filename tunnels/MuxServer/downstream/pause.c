#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDownStreamPause(tunnel_t *t, line_t *child_l)
{
    muxserver_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    child_ls->paused = true;

    muxserver_lstate_t *parent_ls = child_ls->parent;
    if (parent_ls->parent_finishing || child_ls->flow_paused_sent)
    {
        return;
    }

    child_ls->flow_paused_sent = true;
    (void) muxserverSendControlFrame(t, parent_ls->l, parent_ls, child_l, child_ls->connection_id, kMuxFlagFlowPause);
}
