#include "structure.h"

static void tick(wtimer_t *timer)
{
    wireguardclient_tstate_t *state = weventGetUserdata(timer);
    if (atomicLoad(&state->dispatch.open))
    {
        discard wireguardclientEnsureCarrier(state);
        wireguardCommonLoop(&state->engine);
        wireguardclientFlushPending(state);
    }
}

void wireguardclientTunnelOnStart(tunnel_t *t)
{
    wireguardclient_tstate_t *state  = tunnelGetState(t);
    state->engine.first_peer->active = true;
    state->timer                     = wtimerAdd(getWorkerLoop(0), tick, WIREGUARDIF_TIMER_MSECS, INFINITE);
    if (state->timer == NULL)
    {
        startupFailureRecord(1);
        return;
    }
    weventSetUserData(state->timer, state);
}
