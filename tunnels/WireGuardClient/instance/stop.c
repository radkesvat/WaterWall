#include "structure.h"

void wireguardclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    wireguardclient_tstate_t *state = tunnelGetState(t);
    atomicStore(&state->dispatch.open, false);
}

void wireguardclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;

    wireguardclient_tstate_t *state = tunnelGetState(t);
    if (wid == 0 && state->timer != NULL)
    {
        wtimerDelete(state->timer);
        state->timer = NULL;
    }
}

void wireguardclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;

    wireguardclient_tstate_t *state = tunnelGetState(t);
    if (wid != 0)
        return;
    wireguardclientDiscardPending(state);
    if (state->carrier == NULL)
        return;
    line_t *line   = state->carrier;
    state->carrier = NULL;
    memoryZeroAligned32(lineGetState(line, t), t->lstate_size);
    lineRef(line);
    tunnelNextUpStreamFinish(t, line);
    if (lineIsAlive(line))
        lineDestroy(line);
    lineUnref(line);
}
