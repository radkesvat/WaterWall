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

static void discardExpiredPending(wireguardclient_tstate_t *state, uint32_t now)
{
    if (state->pending_count > 0 && now - state->pending_demand_millis >= REKEY_ATTEMPT_TIME * 1000U)
        wireguardclientDiscardPending(state);
}

void wireguardclientFlushPending(wireguardclient_tstate_t *state)
{
    while (state->pending_count > 0)
    {
        discardExpiredPending(state, getTickMS());
        if (state->pending_count == 0 || ! wireguardCommonPeerCanSend(state->engine.first_peer))
            return;

        sbuf_t *packet = wireguardclientTrySendInner(state, takePending(state));
        if (packet != NULL)
        {
            state->pending_head = (state->pending_head + ARRAY_SIZE(state->pending) - 1U) % ARRAY_SIZE(state->pending);
            state->pending[state->pending_head] = packet;
            ++state->pending_count;
            state->pending_charge += sbufGetAllocationCharge(packet);
            return;
        }
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
    if (LIKELY(state->pending_count == 0 && wireguardCommonPeerCanSend(state->engine.first_peer)))
    {
        packet = wireguardclientTrySendInner(state, packet);
        if (packet == NULL)
            return;
    }

    const uint32_t now = getTickMS();
    discardExpiredPending(state, now);
    const size_t charge = sbufGetAllocationCharge(packet);
    if (state->pending_count == ARRAY_SIZE(state->pending) || charge > 1024U * 1024U - state->pending_charge)
    {
        reuseBuffer(packet);
        return;
    }
    state->pending[(state->pending_head + state->pending_count) % ARRAY_SIZE(state->pending)] = packet;
    ++state->pending_count;
    state->pending_charge += charge;
    state->pending_demand_millis = now;
}
