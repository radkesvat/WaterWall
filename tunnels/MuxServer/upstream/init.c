#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelUpStreamInit(tunnel_t *t, line_t *parent_l)
{
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);
    muxserverLinestateInitialize(parent_ls, parent_l, false, 0);
    tunnelPrevDownStreamEst(t, parent_l);
}
