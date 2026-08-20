#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDownStreamFinish(tunnel_t *t, line_t *child_l)
{
    muxserver_lstate_t *child_ls = lineGetState(child_l, t);
    assert(child_ls->is_child);

    if (child_ls->close_state == kMuxServerChildCloseParentGoneDraining)
    {
        // The next side sent Finish, so release retained data without reflecting Finish back to it.
        muxserverAbortDetachedChild(t, child_l, child_ls, false);
        return;
    }

    assert(child_ls->parent);
    muxserver_lstate_t *parent_ls = child_ls->parent;
    line_t             *parent_l  = parent_ls->l;

    // the next side sent us Finish, so nothing may be reflected back toward it
    muxserverCloseChildKeepParent(t, parent_l, parent_ls, child_ls, false);
}
