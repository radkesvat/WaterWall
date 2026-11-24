#include "WireGuardServer/structure.h"

enum
{
    kPendingPacketChargeLimit = 128U * 1024U
};

/* Pending packets are admitted and released under bindings_lock. */
static bool chargePending(server_t *state, const sbuf_t *packet)
{
    const size_t charge = sbufGetAllocationCharge(packet);
    if (charge > kPendingPacketChargeLimit || charge > state->max_pending_rekey_bytes - state->pending_rekey_bytes)
        return false;
    state->pending_rekey_bytes += charge;
    return true;
}

static void unchargePending(server_t *state, const sbuf_t *packet)
{
    const size_t charge = sbufGetAllocationCharge(packet);
    assert(charge <= state->pending_rekey_bytes);
    state->pending_rekey_bytes -= charge;
}

/* All pending buffer and ingress membership changes hold bindings_lock. */
static sbuf_t *takePending(binding_t *binding)
{
    sbuf_t *packet = binding->pending;
    if (packet != NULL)
    {
        unchargePending(binding->server, packet);
        binding->pending = NULL;
    }
    return packet;
}

void wireguardserverDiscardPending(binding_t *binding)
{
    sbuf_t *packet = takePending(binding);
    if (packet != NULL)
        sbufDestroy(packet); /* The producer may own a different worker's pool. */
}

/* Recheck eligibility on every locally generated initiation, including timeout retries. */
bool wireguardserverCanInitiate(void *context, wireguard_peer_t *peer)
{
    server_t  *state   = context;
    binding_t *binding = peer->context;
    if (wireguardserverBindingCurrent(binding) && binding->ingress != NULL &&
        wireguardserverIngressAvailable(binding->ingress, false) &&
        (! state->connection || wireguardserverBindingAuthorized(state, binding)))
        return true;
    mutexLock(&state->bindings_lock);
    wireguardserverDiscardPending(binding);
    mutexUnlock(&state->bindings_lock);
    return false;
}

void wireguardserverKeyUnavailable(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    server_t  *state   = context;
    binding_t *binding = peer->context;
    bool       demand  = false;
    mutexLock(&state->bindings_lock);
    ingress_t *ingress = binding->ingress;
    if (wireguardserverBindingCurrent(binding) && ingress != NULL && wireguardserverIngressAvailable(ingress, false))
    {
        const uint32_t now = getTickMS();
        if (binding->pending != NULL && now - binding->pending_since >= REKEY_ATTEMPT_TIME * 1000U)
            wireguardserverDiscardPending(binding);
        const uint32_t since = state->releasing_since != NULL ? *state->releasing_since : now;
        demand               = binding->pending == NULL && now - since < REKEY_ATTEMPT_TIME * 1000U;
        if (demand && chargePending(state, packet))
        {
            state->has_pending     = true;
            binding->pending       = packet;
            binding->pending_since = since;
            packet                 = NULL;
        }
    }
    mutexUnlock(&state->bindings_lock);
    if (packet != NULL)
        sbufDestroy(packet);
    if (demand)
        wireguardCommonRequestHandshake(&state->engine, peer);
}

/* The captured epoch is revalidated by the ordinary reverse packet path before encryption. */
void wireguardserverServicePendingBinding(server_t *state, binding_t *binding)
{
    mutexLock(&state->bindings_lock);
    sbuf_t *packet = binding->pending;
    if (packet != NULL)
    {
        if (wireguardExpired(binding->pending_since, REKEY_ATTEMPT_TIME))
            wireguardserverDiscardPending(binding);
        else if (wireguardCommonPeerCanSend(binding->peer) && wireguardserverIngressAvailable(binding->ingress, true))
        {
            const uint64_t epoch = binding->epoch;
            const uint32_t since = binding->pending_since;
            packet               = takePending(binding);
            mutexUnlock(&state->bindings_lock);
            wireguardserverSendHeldInner(state, packet, epoch, since);
            return;
        }
        else
            state->has_pending = true;
    }
    mutexUnlock(&state->bindings_lock);
}

void wireguardserverServicePending(server_t *state)
{
    if (! state->has_pending)
        return;
    state->has_pending = false;
    for (binding_t *binding = state->binding_head; binding != NULL; binding = binding->next)
        wireguardserverServicePendingBinding(state, binding);
}
