#include "WireGuardServer/structure.h"

static uint64_t destinationBindingEpoch(server_t *state, const sbuf_t *packet)
{
    ip4_hdr_t header;
    if (sbufGetLength(packet) < sizeof(header))
        return 0;
    sbufRead(packet, &header, sizeof(header));
    if (IPH_V(&header) != 4)
        return 0;

    ip_addr_t destination;
    ipAddrCopyFromIp4(destination, header.dest);
    return wireguardserverSourceEpoch(state, &destination);
}

static void sendInner(tunnel_t *t, sbuf_t *packet, void *argument)
{
    const uint64_t epoch = *(const uint64_t *) argument;
    server_t      *state = tunnelGetState(t);
    if (state->releasing_since == NULL)
        wireguardserverReconcile(state, false);
    /* The destination may have been reassigned since this packet was queued. */
    if (state->connection && UNLIKELY(epoch == 0 || destinationBindingEpoch(state, packet) != epoch))
        goto refuse;
    /* Reconciliation and authorization can take time after a packet leaves its slot. */
    if (state->releasing_since != NULL && wireguardExpired(*state->releasing_since, REKEY_ATTEMPT_TIME))
        goto refuse;
    wireguardCommonSendInner(&state->engine, packet);
    return;
refuse:
    sbufDestroy(packet);
}

void wireguardserverSendHeldInner(server_t *state, sbuf_t *packet, uint64_t epoch, uint32_t since)
{
    /* All other inner deliveries are force-queued. Only this packet can lose its key and return to the pending slot
     * here. */
    assert(state->releasing_since == NULL);
    state->releasing_since = &since;
    sendInner(state->tunnel, packet, &epoch);
    state->releasing_since = NULL;
}

static void freeArgument(void *argument)
{
    memoryFree(argument);
}

void wireguardserverTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    server_t *state = tunnelGetState(t);
    assert(tunnelchainIsWorkerPacketLine(t->chain, line));
    discard   line;
    uint64_t *epoch = memoryAllocate(sizeof(*epoch));
    *epoch          = state->connection ? destinationBindingEpoch(state, packet) : 0;
    wireguardDispatch(&state->dispatch, 0, t, packet, epoch, sendInner, freeArgument);
}
