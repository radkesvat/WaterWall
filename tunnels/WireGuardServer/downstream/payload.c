#include "WireGuardServer/structure.h"

static void sendInner(tunnel_t *t, sbuf_t *packet, void *argument)
{
    const uint64_t epoch = *(const uint64_t *) argument;
    server_t      *state = tunnelGetState(t);
    if (state->releasing_since == NULL)
        wireguardserverReconcile(state, false);
    if (state->connection)
    {
        if (UNLIKELY(sbufGetLength(packet) < 20 || (sbufGetRawPtr(packet)[0] >> 4U) != 4))
            goto refuse;
        ip_addr_t  ip;
        ip4_addr_t address;
        memoryCopy(&address.addr, sbufGetRawPtr(packet) + 16, 4);
        ipAddrCopyFromIp4(ip, address);
        if (UNLIKELY(epoch == 0 || wireguardserverSourceEpoch(state, &ip) != epoch))
            goto refuse;
    }
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
    *epoch          = 0;
    if (state->connection && sbufGetLength(packet) >= 20 && (sbufGetRawPtr(packet)[0] >> 4U) == 4)
    {
        ip_addr_t  ip;
        ip4_addr_t address;
        memoryCopy(&address.addr, sbufGetRawPtr(packet) + 16, 4);
        ipAddrCopyFromIp4(ip, address);
        *epoch = wireguardserverSourceEpoch(state, &ip);
    }
    wireguardDispatch(&state->dispatch, 0, t, packet, epoch, sendInner, freeArgument);
}
