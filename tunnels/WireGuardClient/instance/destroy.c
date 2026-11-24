#include "structure.h"

void wireguardclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    wireguardclient_tstate_t *state = tunnelGetState(t);
    assert(state->pending_count == 0 && state->carrier == NULL && atomicLoad(&state->dispatch.count) == 0);
    addresscontextReset(&state->endpoint);
    wireguardDeviceDestroy(&state->engine);
    tunnelDestroy(t);
}
