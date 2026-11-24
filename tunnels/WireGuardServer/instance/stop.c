#include "WireGuardServer/structure.h"

void wireguardserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    server_t *state = tunnelGetState(t);
    atomicStore(&state->dispatch.open, false);
}

void wireguardserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard   context;
    server_t *state = tunnelGetState(t);
    if (wid != 0)
        return;
    if (state->timer != NULL)
    {
        wtimerDelete(state->timer);
        state->timer = NULL;
    }
    mutexLock(&state->bindings_lock);
    for (binding_t *binding = state->binding_head; binding != NULL; binding = binding->next)
        wireguardserverDiscardPending(binding);
    mutexUnlock(&state->bindings_lock);
}

void wireguardserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard   context;
    server_t *state = tunnelGetState(t);
    while (state->ingress_heads != NULL && state->ingress_heads[wid] != NULL)
    {
        line_t *line = state->ingress_heads[wid]->line;
        lineRef(line);
        wireguardserverDetachIngress(t, line);
        tunnelPrevDownStreamFinish(t, line);
        lineUnref(line);
    }
}
