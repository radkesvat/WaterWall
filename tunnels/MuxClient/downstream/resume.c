#include "structure.h"

void muxclientTunnelDownStreamResume(tunnel_t *t, line_t *parent_l)
{
    muxclient_tstate_t *ts     = tunnelGetState(t);
    muxclient_lstate_t *parent = lineGetState(parent_l, t);
    if (ts->worker_states[lineGetWID(parent_l)].quiescing || parent->parent_finishing)
        return;
    parent->parent_state->output.transport_paused = false;
    muxclientDrainParentOutput(t, parent_l);
}
