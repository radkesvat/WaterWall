#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDownStreamResume(tunnel_t *t, line_t *child_l)
{
    muxserver_tstate_t *ts_shutdown = tunnelGetState(t);
    if (ts_shutdown->worker_states[lineGetWID(child_l)].quiescing)
    {
        return;
    }

    muxserver_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    child_ls->paused = false;

    if (child_ls->close_state == kMuxServerChildCloseParentGoneDraining)
    {
        muxserver_child_drain_result_t result = muxserverDrainDetachedChild(t, child_l, child_ls);
        if (result == kMuxServerChildDrainReadyToFinish)
        {
            muxserverFinalizeDetachedChild(t, child_l, child_ls);
        }
        return;
    }

    muxserver_lstate_t *parent_ls = child_ls->parent;
    if (parent_ls->parent_finishing)
    {
        return;
    }

    muxserver_child_drain_result_t result = muxserverDrainAttachedChild(t, parent_ls->l, parent_ls, child_l, child_ls);
    if (result == kMuxServerChildDrainReadyToFinish && child_ls->close_state == kMuxServerChildClosePeerDraining)
    {
        discard muxserverFinalizeAttachedPeerClose(t, parent_ls->l, parent_ls, child_ls);
    }
}
