#include "WireGuardServer/structure.h"

typedef struct receive_s
{
    ingress_t *ingress;
    uint64_t   generation;
} receive_t;

static void releaseReceive(void *argument)
{
    receive_t *received = argument;
    wireguardserverIngressRelease(received->ingress);
    memoryFree(received);
}

static void receive(tunnel_t *t, sbuf_t *packet, void *argument)
{
    server_t  *state    = tunnelGetState(t);
    receive_t *received = argument;
    ingress_t *ingress  = received->ingress;
    wireguardserverReconcile(state, false);
    if (UNLIKELY(! wireguardserverIngressAvailable(ingress, false)))
    {
        reuseBuffer(packet);
        return;
    }
    state->received_binding     = NULL;
    state->receiving            = ingress;
    state->receiving_generation = received->generation;
    wireguardCommonReceive(&state->engine, packet, &ingress->ip, ingress->port);
    state->receiving            = NULL;
    state->receiving_generation = 0;
    if (state->received_binding != NULL)
        wireguardserverServicePendingBinding(state, state->received_binding);
    state->received_binding = NULL;
    /* The sole provisional candidate belongs to this owner's synchronous receive. */
    if (state->provisional != NULL)
        wireguardserverClearBinding(state, state->provisional);
}

void wireguardserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    server_t      *state = tunnelGetState(t);
    server_line_t *ls    = lineGetState(line, t);
    if (UNLIKELY(ls->ingress == NULL))
    {
        lineReuseBuffer(line, packet);
        return;
    }
    if (UNLIKELY(atomicLoad(&ls->ingress->closing)))
    {
        lineReuseBuffer(line, packet);
        wireguardserverCloseOrphanIngress(t, line);
        return;
    }
    receive_t *received = memoryAllocate(sizeof(*received));
    *received           = (receive_t) {.ingress    = ls->ingress,
                                       .generation = state->connection ? authenticationclientUsersGeneration(state->auth) : 0};
    wireguardserverIngressRetain(ls->ingress);
    wireguardDispatch(&state->dispatch, 0, t, packet, received, receive, releaseReceive);
}
