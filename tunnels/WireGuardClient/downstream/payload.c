#include "structure.h"

void wireguardclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *packet)
{
    wireguardclient_tstate_t *state = tunnelGetState(t);
    assert(currentThreadOwnsWorker(0));
    if (UNLIKELY(state->carrier != l || ! atomicLoad(&state->dispatch.open)))
    {
        lineReuseBuffer(l, packet);
        return;
    }
    wireguardCommonReceiveOnCarrier(&state->engine, packet, state->carrier_id);
    wireguardclientFlushPending(state);
}
