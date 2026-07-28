#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDownStreamFinish(tunnel_t *t, line_t *child_l)
{
    muxserver_lstate_t *child_ls = lineGetState(child_l, t);
    assert(child_ls->is_child);

    assert(child_ls->parent);

    muxserver_lstate_t *parent_ls = child_ls->parent;
    line_t             *parent_l  = parent_ls->l;

    // the next side sent us Finish, so nothing may be reflected back toward it
    muxserverCloseChildKeepParent(t, parent_l, parent_ls, child_ls, false);
}
