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

static void keyUnavailable(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    discard peer;

    wireguardclient_tstate_t *state = context;
    assert(state->key_refused_packet != NULL && *state->key_refused_packet == NULL);
    *state->key_refused_packet = packet;
}

sbuf_t *wireguardclientTrySendInner(wireguardclient_tstate_t *state, sbuf_t *packet)
{
    /* Carrier output can reenter the client. Each send owns its own refusal result. */
    sbuf_t  *refused          = NULL;
    sbuf_t **outer            = state->key_refused_packet;
    state->key_refused_packet = &refused;
    wireguardCommonSendInner(&state->engine, packet);
    state->key_refused_packet = outer;
    return refused;
}

const wireguard_callbacks_t wireguardclientEngineCallbacks = {
    .output          = sendToCarrier,
    .inner           = deliverInner,
    .key_unavailable = keyUnavailable,
};
