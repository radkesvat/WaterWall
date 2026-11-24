#include "structure.h"

static bool sendToCarrier(void *context, sbuf_t *packet, wireguard_peer_t *selected_peer, const ip_addr_t *ip,
                          uint16_t port)
{
    discard selected_peer;
    discard ip;
    discard port;

    wireguardclient_tstate_t *state = context;
    line_t                   *line  = wireguardclientEnsureCarrier(state);
    if (line == NULL || state->paused || ! atomicLoad(&state->dispatch.open))
    {
        reuseBuffer(packet);
        return false;
    }
    discard lineCallWithRefWithBuf(line, tunnelNextUpStreamPayload, state->tunnel, packet);
    return true;
}

static void deliverInner(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    discard peer;

    wireguardclient_tstate_t *state = context;
    line_t                   *line  = tunnelchainGetWorkerPacketLine(state->tunnel->chain, 0);
    tunnelPrevDownStreamPayload(state->tunnel, line, packet);
}

const wireguard_callbacks_t wireguardclientEngineCallbacks = {
    .output = sendToCarrier,
    .inner  = deliverInner,
};
