#include "WireGuardServer/structure.h"

void wireguardserverTunnelUpStreamInit(tunnel_t *t, line_t *line)
{
    server_t *state = tunnelGetState(t);
    assert(! tunnelchainIsWorkerPacketLine(t->chain, line));
    server_line_t *ls                    = lineGetState(line, t);
    *ls                                  = (server_line_t) {0};
    const address_context_t *source      = lineGetSourceAddressContext(line);
    address_context_t       *destination = lineGetDestinationAddressContext(line);
    /* UDP ingress keeps the remote port separately from its local listener port. */
    const uint16_t peer_port = lineGetRoutingContext(line)->peer_source_port;
    if (UNLIKELY(! atomicLoad(&state->dispatch.open) || ! addresscontextIsIpType(source) || peer_port == 0))
    {
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    if (addresscontextSelectTransport(destination, kAddressContextTransportUdp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportUdp);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    addresscontextSetOnlyProtocol(destination, IP_PROTO_UDP);
    if (! wireguardserverReserveFreshIngress(state))
    {
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    ingress_t *ingress = memoryAllocateZero(sizeof(*ingress));
    if (UNLIKELY(! mutexTryInit(&ingress->lock)))
    {
        memoryFree(ingress);
        mutexLock(&state->bindings_lock);
        --state->unauthenticated_ingress;
        mutexUnlock(&state->bindings_lock);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    atomic_init(&ingress->references, 1);
    atomic_init(&ingress->closing, false);
    atomicAdd(&state->ingress_count, 1);
    ingress->awaiting_proof = true;
    ingress->line           = line;
    ingress->worker         = lineGetWID(line);
    ingress->ip             = source->ip_address;
    ingress->port           = peer_port;
    lineRef(line);
    ls->ingress   = ingress;
    ingress->next = state->ingress_heads[ingress->worker];
    if (ingress->next != NULL)
        ingress->next->previous = ingress;
    state->ingress_heads[ingress->worker] = ingress;
    tunnelPrevDownStreamEst(t, line);
}
