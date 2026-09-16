#include "structure.h"

void muxserverTunnelUpStreamPause(tunnel_t *t, line_t *parent_l)
{
    muxserver_tstate_t *ts     = tunnelGetState(t);
    muxserver_lstate_t *parent = lineGetState(parent_l, t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing)
        return;
    parent->parent_state->output.transport_paused = true;
}
