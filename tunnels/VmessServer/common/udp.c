#include "internal.h"

bool vmessserverUdpMember(tunnel_t *t, const vmessserver_lstate_t *client, line_t *remote)
{
    if (! client->packetaddr)
        return client->udp_remote_line == remote;
    const vmessserver_lstate_t *backend = lineGetState(remote, t);
    const vmessserver_tstate_t *ts      = tunnelGetState(t);
    return client->udp_destinations != NULL && backend->udp_slot < ts->packetaddr_max_destinations &&
           client->udp_destinations[backend->udp_slot] == remote;
}

void vmessserverSetUdpBackendPaused(tunnel_t *t, line_t *remote_l, bool paused)
{
    vmessserver_lstate_t *remote   = lineGetState(remote_l, t);
    line_t               *client_l = remote->client_line;
    if (client_l == NULL || ! lineIsAlive(client_l))
        return;
    vmessserver_lstate_t *client = lineGetState(client_l, t);
    if (! vmessserverUdpMember(t, client, remote_l))
        return;
    if (remote->backend_paused != paused)
    {
        remote->backend_paused = paused;
        if (paused)
            ++client->paused_backends;
        else
        {
            assert(client->paused_backends != 0);
            --client->paused_backends;
        }
    }
    client->udp_backend_paused = client->paused_backends != 0;
    vmessserverReconcileUdpSourcePermission(t, client_l);
}

/* Permission is published before callbacks. Restart the bounded table search
 * after every handoff; reentry may retire any sibling or change permission. */
void vmessserverNotifyUdpPermission(tunnel_t *t, line_t *client_l)
{
    vmessserver_lstate_t *client = lineGetState(client_l, t);
    if (client->permission_dispatching)
    {
        client->permission_pending = true;
        return;
    }
    lineRef(client_l);
    client->permission_dispatching = true;
    do
    {
        client->permission_pending = false;
        for (;;)
        {
            line_t                     *notify = NULL;
            const vmessserver_tstate_t *ts     = tunnelGetState(t);
            const size_t                limit  = client->packetaddr ? ts->packetaddr_max_destinations : 1;
            for (size_t i = 0; i < limit; ++i)
            {
                line_t *remote_l = client->packetaddr ? client->udp_destinations[i] : client->udp_remote_line;
                if (remote_l != NULL)
                {
                    vmessserver_lstate_t *remote = lineGetState(remote_l, t);
                    if (remote->backend_pause_sent != client->response_paused)
                    {
                        remote->backend_pause_sent = client->response_paused;
                        notify                     = remote_l;
                        break;
                    }
                }
            }
            if (notify == NULL)
                break;
            if (client->response_paused)
                discard lineCallWithRef(notify, tunnelNextUpStreamPause, t);
            else
                discard lineCallWithRef(notify, tunnelNextUpStreamResume, t);
            if (! lineIsAlive(client_l) || client->tunnel != t || client->phase == kVmessServerPhaseClosing)
            {
                lineUnref(client_l);
                return;
            }
        }
    } while (client->permission_pending);
    client->permission_dispatching = false;
    lineUnref(client_l);
}

static bool sameTarget(const address_context_t *a, const address_context_t *b)
{
    if (a->port != b->port || ! addresscontextIsIpType(a) || ! addresscontextIsIpType(b) ||
        addresscontextIsIpv4(a) != addresscontextIsIpv4(b))
        return false;
    return addresscontextIsIpv4(a) ? memoryEqual(&a->ip_address.u_addr.ip4.addr, &b->ip_address.u_addr.ip4.addr, 4)
                                   : memoryEqual(&a->ip_address.u_addr.ip6, &b->ip_address.u_addr.ip6, 16);
}

static line_t *getOrCreateRemote(tunnel_t *t, line_t *client_l, vmessserver_lstate_t *client,
                                 const address_context_t *target)
{
    vmessserver_tstate_t *ts   = tunnelGetState(t);
    size_t                slot = 0;
    if (! client->packetaddr)
    {
        if (client->udp_remote_line != NULL)
            return client->udp_remote_line;
    }
    else
    {
        slot = ts->packetaddr_max_destinations;
        for (size_t i = 0; i < ts->packetaddr_max_destinations; ++i)
        {
            line_t *remote = client->udp_destinations[i];
            if (remote == NULL)
            {
                if (slot == ts->packetaddr_max_destinations)
                    slot = i;
            }
            else if (sameTarget(&((vmessserver_lstate_t *) lineGetState(remote, t))->udp_target, target))
                return remote;
        }
        if (slot == ts->packetaddr_max_destinations)
        {
            vmessserverDrop(client, kVmessServerReasonDestinationCapacity);
            return NULL;
        }
    }
    /* Existing backends may receive final bytes; shutdown never recreates them. */
    if (client->phase == kVmessServerPhaseClosing || ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(client_l))))
        return NULL;
    assert(addresscontextHasPort(target));
    line_t               *remote_l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    vmessserver_lstate_t *remote   = lineGetState(remote_l, t);
    vmessserverLinestateInitialize(remote, t, remote_l, kVmessServerLineKindUdpRemote);
    remote->client_line          = client_l;
    remote->client_line_ref_held = true;
    remote->user_handle          = client->user_handle;
    remote->phase                = kVmessServerPhaseUdpConnecting;
    remote->udp_slot             = (uint16_t) slot;
    addresscontextCopy(&remote->udp_target, target);
    lineRef(client_l);
    lineGetRoutingContext(remote_l)->local_listener_port = lineGetRoutingContext(client_l)->local_listener_port;
    addresscontextCopy(lineGetSourceAddressContext(remote_l), lineGetSourceAddressContext(client_l));
    lineCopyUsers(remote_l, client_l);
    vmessserverApplyDestinationContext(remote_l, target, true);
    if (client->packetaddr)
    {
        client->udp_destinations[slot] = remote_l;
        ++client->udp_destination_count;
    }
    else
        client->udp_remote_line = remote_l;
    wid_t wid          = lineGetWID(client_l);
    remote->owned_next = ts->owned_backends[wid];
    if (remote->owned_next != NULL)
        remote->owned_next->owned_prev = remote;
    ts->owned_backends[wid] = remote;
    if (! lineCallWithRef(remote_l, tunnelNextUpStreamInit, t))
        return NULL;
    if (! lineIsAlive(client_l) || client->tunnel != t || ! vmessserverUdpMember(t, client, remote_l))
        return NULL;
    if (client->response_paused)
    {
        remote->backend_pause_sent = true;
        if (! lineCallWithRef(remote_l, tunnelNextUpStreamPause, t))
            return NULL;
    }
    if (! lineIsAlive(client_l) || client->tunnel != t || ! vmessserverUdpMember(t, client, remote_l))
        return NULL;
    return remote_l;
}

bool vmessserverStartUdpBranch(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, const address_context_t *target)
{
    addresscontextCopy(&ls->udp_target, target);
    ls->phase = kVmessServerPhaseUdpConnecting;
    lineRef(l);
    line_t *remote = getOrCreateRemote(t, l, ls, target);
    bool    alive  = lineIsAlive(l) && ls->tunnel == t;
    if (alive && remote == NULL)
        vmessserverCloseLineBidirectional(t, l);
    lineUnref(l);
    return alive && remote != NULL;
}

bool vmessserverDeliverDecoded(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    vmessserver_lstate_t *ls = lineGetState(line, t);
    if (ls->next_finished)
    {
        lineReuseBuffer(line, payload);
        return false;
    }
    vmessserver_tstate_t *ts = tunnelGetState(t);
    if (ls->request.command == kVmessCmdTcp)
    {
        atomicAddU64(&ts->stats.rx_application_bytes, sbufGetLength(payload));
        if (! lineCallWithRefWithBuf(line, tunnelNextUpStreamPayload, t, payload))
            return false;
        return ((vmessserver_lstate_t *) lineGetState(line, t))->tunnel == t;
    }
    address_context_t target = {0};
    if (ls->packetaddr)
    {
        vmess_packet_addr_t address;
        size_t              prefix = 0;
        if (vmessPacketAddrDecode(sbufGetRawPtr(payload), sbufGetLength(payload), &address, &prefix) != kWCryptoOk)
        {
            vmessserverReason(ls, kVmessServerReasonPacketAddr);
            lineReuseBuffer(line, payload);
            vmessserverCloseLineBidirectional(t, line);
            return false;
        }
        ip_addr_t ip = {0};
        ip.type      = address.address_type == kVmessAtypIpv4 ? IPADDR_TYPE_V4 : IPADDR_TYPE_V6;
        memoryCopy(address.address_type == kVmessAtypIpv4 ? (void *) &ip.u_addr.ip4.addr : (void *) &ip.u_addr.ip6,
                   address.address,
                   address.address_type == kVmessAtypIpv4 ? 4 : 16);
        addresscontextSetIpPort(&target, &ip, address.port);
        sbufShiftRight(payload, (uint32_t) prefix);
    }
    else
        addresscontextCopy(&target, &ls->udp_target);
    buffer_pool_t *pool = lineGetBufferPool(line);
    lineRef(line);
    line_t *remote = getOrCreateRemote(t, line, ls, &target);
    addresscontextReset(&target);
    if (! lineIsAlive(line) || ls->tunnel != t)
    {
        bufferpoolReuseBuffer(pool, payload);
        lineUnref(line);
        return false;
    }
    if (remote == NULL)
    {
        bufferpoolReuseBuffer(pool, payload);
        /* Packetaddr drops only this destination/datagram; existing entries and
         * independent backend Init failures leave the carrier available. */
        bool packetaddr = ls->packetaddr;
        if (! packetaddr)
            vmessserverCloseLineBidirectional(t, line);
        lineUnref(line);
        return packetaddr;
    }
    atomicAddU64(&ts->stats.rx_application_bytes, sbufGetLength(payload));
    discard lineCallWithRefWithBuf(remote, tunnelNextUpStreamPayload, t, payload);
    bool    alive = lineIsAlive(line) && ls->tunnel == t;
    lineUnref(line);
    return alive;
}
