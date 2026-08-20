#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamResume(tunnel_t *t, line_t *child_l)
{
    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    child_ls->paused = false;

    if (child_ls->close_state == kMuxClientChildCloseParentGoneDraining)
    {
        muxclient_child_drain_result_t result = muxclientDrainDetachedChild(t, child_l, child_ls);
        if (result == kMuxClientChildDrainReadyToFinish)
        {
            muxclientFinalizeDetachedChild(t, child_l, child_ls);
        }
        return;
    }

    muxclient_lstate_t *parent_ls = child_ls->parent;
    if (parent_ls->parent_finishing || ! child_ls->open_frame_sent)
    {
        return;
    }

    muxclient_child_drain_result_t result = muxclientDrainAttachedChild(t, parent_ls->l, parent_ls, child_l, child_ls);
    if (result == kMuxClientChildDrainReadyToFinish && child_ls->close_state == kMuxClientChildClosePeerDraining)
    {
        discard muxclientFinalizeAttachedPeerClose(t, parent_ls->l, tunnelGetState(t), parent_ls, child_ls);
    }
}
