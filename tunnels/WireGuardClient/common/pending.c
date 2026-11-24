#include "structure.h"

static sbuf_t *takePending(wireguardclient_tstate_t *state)
{
    sbuf_t *packet                      = state->pending[state->pending_head];
    state->pending[state->pending_head] = NULL;
    state->pending_head                 = (state->pending_head + 1U) % ARRAY_SIZE(state->pending);
    --state->pending_count;
    state->pending_charge -= sbufGetAllocationCharge(packet);
    return packet;
}

void wireguardclientFlushPending(wireguardclient_tstate_t *state)
{
    while (state->pending_count > 0 && wireguardCommonPeerCanSend(state->engine.first_peer))
    {
        wireguardCommonSendInner(&state->engine, takePending(state));
    }
}

void wireguardclientDiscardPending(wireguardclient_tstate_t *state)
{
    while (state->pending_count > 0)
    {
        reuseBuffer(takePending(state));
    }
}

void wireguardclientSendInner(tunnel_t *t, sbuf_t *packet, void *argument)
{
    discard argument;

    wireguardclient_tstate_t *state = tunnelGetState(t);

    discard wireguardclientEnsureCarrier(state);
    wireguardclientFlushPending(state);
    if (LIKELY(wireguardCommonPeerCanSend(state->engine.first_peer)))
    {
        wireguardCommonSendInner(&state->engine, packet);
        return;
    }
    const size_t charge = sbufGetAllocationCharge(packet);
    if (state->pending_count == ARRAY_SIZE(state->pending) || charge > 1024U * 1024U - state->pending_charge)
    {
        reuseBuffer(packet);
        return;
    }
    state->pending[(state->pending_head + state->pending_count) % ARRAY_SIZE(state->pending)] = packet;
    ++state->pending_count;
    state->pending_charge += charge;
}
