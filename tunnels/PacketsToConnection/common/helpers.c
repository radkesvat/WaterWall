#include "structure.h"

bool ptcNextGateEnter(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(ptcTunnelIsStopping(t) || ! quiescenceGateEnter(&state->next_gate)))
    {
        return false;
    }
    if (UNLIKELY(ptcTunnelIsStopping(t)))
    {
        quiescenceGateLeave(&state->next_gate);
        return false;
    }
    return true;
}

void ptcNextGateLeave(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);
    quiescenceGateLeave(&state->next_gate);
}

bool ptcTunnelIsStopping(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);
    return atomicLoadRelaxed(&state->stopping);
}
