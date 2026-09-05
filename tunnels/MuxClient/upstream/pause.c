#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamPause(tunnel_t *t, line_t *child_l)
{
    muxclient_tstate_t *ts_shutdown = tunnelGetState(t);
    if (ts_shutdown->worker_states[lineGetWID(child_l)].quiescing)
    {
        return;
    }

    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    child_ls->paused = true;

    if (child_ls->close_state != kMuxClientChildCloseOpen)
    {
        return;
    }

    muxclient_lstate_t *parent_ls = child_ls->parent;
    if (parent_ls->parent_finishing || ! child_ls->open_frame_sent)
    {
        return;
    }

    discard muxclientSendChildFlowPause(t, parent_ls->l, parent_ls, child_l, child_ls);
}
