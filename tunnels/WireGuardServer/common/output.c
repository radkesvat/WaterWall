#include "WireGuardServer/structure.h"

typedef struct send_s
{
    ingress_t *ingress;
    uint64_t   epoch;
} send_t;

static void releaseSend(void *argument)
{
    send_t *send = argument;
    wireguardserverIngressRelease(send->ingress);
    memoryFree(send);
}

static void sendOnIngress(tunnel_t *t, sbuf_t *packet, void *argument)
{
    server_t *state = tunnelGetState(t);
    send_t   *send  = argument;
    if (send->epoch != 0)
    {
        authenticationclient_wireguard_authorization_t expected = {0};
        uint8_t                                        key[32]  = {0};
        mutexLock(&state->bindings_lock);
        const binding_t *binding = wireguardserverBindingByEpoch(state, send->epoch);
        bool             valid   = wireguardserverBindingCurrent(binding);
        if (valid && state->connection)
        {
            expected.handle     = binding->authorization.handle;
            expected.network    = binding->authorization.network;
            expected.mask       = binding->authorization.mask;
            expected.continuity = binding->authorization.continuity;
            memoryCopy(key, binding->public_key, sizeof(key));
        }
        mutexUnlock(&state->bindings_lock);
        if (valid && state->connection)
            valid = authenticationclientWireGuardAuthorizationMatches(
                state->auth, key, &expected.handle, expected.continuity, &expected.network, &expected.mask);
        mutexLock(&state->bindings_lock);
        valid = valid && wireguardserverBindingCurrent(wireguardserverBindingByEpoch(state, send->epoch));
        mutexUnlock(&state->bindings_lock);
        if (UNLIKELY(! valid))
        {
            sbufDestroy(packet);
            return;
        }
    }
    ingress_t *ingress = send->ingress;
    mutexLock(&ingress->lock);
    line_t *line = ingress->line;
    /* Admission checked Pause before posting. A later Pause leaves this accepted datagram in flight. */
    if (line != NULL)
        lineRef(line);
    mutexUnlock(&ingress->lock);
    if (line == NULL)
    {
        sbufDestroy(packet);
        return;
    }
    tunnelPrevDownStreamPayload(t, line, packet);
    lineUnref(line);
}

bool wireguardserverOutput(void *context, sbuf_t *packet, wireguard_peer_t *selected_peer, const ip_addr_t *ip,
                           uint16_t port)
{
    server_t  *state    = context;
    ingress_t *ingress  = NULL;
    send_t     snapshot = {0};
    if (selected_peer != NULL && selected_peer->valid)
    {
        binding_t *binding = selected_peer->context;
        if (wireguardserverBindingCurrent(binding) && ipAddrCmp(&selected_peer->ip, ip) && selected_peer->port == port)
        {
            ingress        = binding->ingress;
            snapshot.epoch = binding->epoch;
        }
    }
    if (ingress == NULL && state->receiving != NULL && ipAddrCmp(&state->receiving->ip, ip) &&
        state->receiving->port == port)
        ingress = state->receiving;
    if (ingress == NULL || ! wireguardserverIngressAvailable(ingress, true))
    {
        /* In-place encryption can preserve an inner producer's original allocation. */
        sbufDestroy(packet);
        return false;
    }
    send_t *send  = memoryAllocate(sizeof(*send));
    *send         = snapshot;
    send->ingress = ingress;
    wireguardserverIngressRetain(ingress);
    return wireguardDispatch(
        &state->dispatch, ingress->worker, state->tunnel, packet, send, sendOnIngress, releaseSend);
}

void wireguardserverInner(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    server_t  *state   = context;
    binding_t *binding = peer->context;
    if (UNLIKELY(! wireguardserverBindingCurrent(binding)))
    {
        reuseBuffer(packet);
        return;
    }
    line_t *line = tunnelchainGetWorkerPacketLine(state->tunnel->chain, 0);
    tunnelNextUpStreamPayload(state->tunnel, line, packet);
}
