#include "structure.h"

#include "loggers/network_logger.h"

#include "loggers/dns_logger.h"

typedef enum udpconnector_packet_peer_result_e
{
    kUdpConnectorPacketPeerReady = 0,
    kUdpConnectorPacketPeerConsumed
} udpconnector_packet_peer_result_e;

static void handleQueueOverflow(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls)
{
    discard ts;
    LOGE("UdpConnector: upstream write queue overflow, size: %d, limit: %d",
         (int) udpconnectorQueuedWriteBytes(ls),
         (int) kUdpMaxPauseQueueSize);

    udpconnectorLineDetach(t, l, ls, kUdpConnectorDetachQueueOverflow);
}

static void handleQueuedWrite(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls, sbuf_t *buf)
{
    if (! ls->queue_pause_sent && udpconnectorQueuedWriteBytes(ls) > kUdpMinPauseQueueSize)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);
        if (! lineCallWithRef(l, tunnelPrevDownStreamPause, t))
        {
            bufferpoolReuseBuffer(pool, buf);
            return;
        }
        ls->queue_pause_sent = true;
    }

    bufferqueuePushBack(&ls->pause_queue, buf);

    if (udpconnectorQueuedWriteBytes(ls) > kUdpMaxPauseQueueSize)
    {
        handleQueueOverflow(t, l, ts, ls);
    }
}

static void udpconnectorPacketDnsRequestDestroy(udpconnector_packet_dns_request_t *request)
{
    memoryFree(request->domain);
    memoryFree(request);
}

static void udpconnectorPacketDnsRequestLink(udpconnector_lstate_t *ls, udpconnector_packet_dns_request_t *request)
{
    request->prev = NULL;
    request->next = ls->packet_dns_requests;

    if (ls->packet_dns_requests != NULL)
    {
        ls->packet_dns_requests->prev = request;
    }

    ls->packet_dns_requests = request;
}

static void udpconnectorPacketDnsRequestUnlink(udpconnector_lstate_t *ls, udpconnector_packet_dns_request_t *request)
{
    if (request->prev != NULL)
    {
        request->prev->next = request->next;
    }
    else if (ls->packet_dns_requests == request)
    {
        ls->packet_dns_requests = request->next;
    }

    if (request->next != NULL)
    {
        request->next->prev = request->prev;
    }

    request->prev = NULL;
    request->next = NULL;
}

static void udpconnectorWriteUsingBinding(line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls,
                                          udpconnector_binding_t *binding, sbuf_t *buf)
{
    assert(binding != NULL && binding->active && binding->socket != NULL);
    assert(binding->socket->io != NULL && ! wioIsClosed(binding->socket->io));
    assert(ls->idle_handle != NULL);

    localidletableKeepIdleItemForAtleast(udpconnectorGetLineIdleTable(ts, l), ls->idle_handle, kUdpKeepExpireTime);
    ls->last_send_binding = binding;

    wioWriteDatagram(binding->socket->io, buf, &binding->peer_addr);
}

static udpconnector_binding_t *udpconnectorSelectSendBinding(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts,
                                                             udpconnector_lstate_t *ls, const sockaddr_u *peer_addr)
{
    if (ts->balance_mode == kUdpConnectorBalanceModeConnection || ls->route_destination_pinned)
    {
        udpconnector_binding_t *binding = ls->fixed_binding;
        assert(binding != NULL && binding->active);
        return binding;
    }

    return udpconnectorAcquireBinding(t, l, ls, peer_addr);
}

static void udpconnectorWriteToPeer(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls,
                                    sbuf_t *buf, const sockaddr_u *peer_addr)
{
    udpconnector_binding_t *binding = udpconnectorSelectSendBinding(t, l, ts, ls, peer_addr);
    if (binding == NULL)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    udpconnectorWriteUsingBinding(l, ts, ls, binding, buf);
}

static bool udpconnectorMaybeResumeQueuedSender(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls)
{
    if (! ls->queue_pause_sent || ls->write_paused || udpconnectorQueuedWriteBytes(ls) > 0)
    {
        return true;
    }

    ls->queue_pause_sent = false;
    return lineCallWithRef(l, tunnelPrevDownStreamResume, t);
}

static void udpconnectorPacketDestinationDropPending(udpconnector_packet_destination_t *cache)
{
    bufferqueueDestroy(&cache->pending_queue);
    cache->pending_queue = bufferqueueCreate(kUdpPauseQueueCapacity);
}

static bool udpconnectorPacketDestinationFail(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                              udpconnector_packet_destination_t *cache)
{
    cache->resolving   = false;
    cache->has_context = false;
    addresscontextReset(&cache->dest_ctx);
    udpconnectorPacketDestinationDropPending(cache);
    return udpconnectorMaybeResumeQueuedSender(t, l, ls);
}

static bool udpconnectorFlushPacketDestinationQueue(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts,
                                                    udpconnector_lstate_t *ls, udpconnector_packet_destination_t *cache)
{
    sockaddr_u              peer_addr = addresscontextToSockAddr(&cache->dest_ctx);
    udpconnector_binding_t *binding   = udpconnectorSelectSendBinding(t, l, ts, ls, &peer_addr);
    if (binding == NULL)
    {
        LOGE("UdpConnector: failed to acquire a UDP binding for resolved packet destination");
        return udpconnectorPacketDestinationFail(t, l, ls, cache);
    }

    while (bufferqueueGetBufCount(&cache->pending_queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&cache->pending_queue);
        udpconnectorWriteUsingBinding(l, ts, ls, binding, buf);
    }

    return udpconnectorMaybeResumeQueuedSender(t, l, ls);
}

static bool udpconnectorQueuePacketForDestination(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts,
                                                  udpconnector_lstate_t *ls, udpconnector_packet_destination_t *cache,
                                                  sbuf_t *buf)
{
    if (! ls->queue_pause_sent && udpconnectorQueuedWriteBytes(ls) > kUdpMinPauseQueueSize)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);
        if (! lineCallWithRef(l, tunnelPrevDownStreamPause, t))
        {
            bufferpoolReuseBuffer(pool, buf);
            return false;
        }
        ls->queue_pause_sent = true;
    }

    bufferqueuePushBack(&cache->pending_queue, buf);

    if (udpconnectorQueuedWriteBytes(ls) > kUdpMaxPauseQueueSize)
    {
        handleQueueOverflow(t, l, ts, ls);
        return false;
    }

    return true;
}

static void udpconnectorOnPacketDnsResolved(void *userdata, int status, const char *error,
                                            const dns_resolved_addr_t *addrs, size_t naddrs)
{
    udpconnector_packet_dns_request_t *request = userdata;
    line_t                            *line    = request->line;

    if (request->cancelled || ! lineIsAlive(line))
    {
        lineUnref(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    tunnel_t                  *t  = request->tunnel;
    udpconnector_lstate_t     *ls = lineGetState(line, t);
    udpconnector_tstate_t     *ts = tunnelGetState(t);
    const dns_resolved_addr_t *selected;

    udpconnectorPacketDnsRequestUnlink(ls, request);

    assert(request->destination_index < ls->packet_destinations_count);
    assert(ls->packet_destinations != NULL);

    udpconnector_packet_destination_t *cache = &ls->packet_destinations[request->destination_index];
    cache->resolving                         = false;

    if (asyncdnsStatusIsShutdown(status))
    {
        discard udpconnectorPacketDestinationFail(t, line, ls, cache);
        lineUnref(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "UdpConnector: async dns resolve failed for %s: %s",
                    request->domain,
                    error != NULL ? error : ares_strerror(status));
        if (! udpconnectorPacketDestinationFail(t, line, ls, cache))
        {
            lineUnref(line);
            udpconnectorPacketDnsRequestDestroy(request);
            return;
        }
        lineUnref(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    selected = udpconnectorSelectResolvedAddress(addrs, naddrs, request->strategy);
    if (! udpconnectorApplyResolvedAddress(&cache->dest_ctx, selected))
    {
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "UdpConnector: async dns resolve returned no usable address for %s",
                    request->domain);
        if (! udpconnectorPacketDestinationFail(t, line, ls, cache))
        {
            lineUnref(line);
            udpconnectorPacketDnsRequestDestroy(request);
            return;
        }
        lineUnref(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    cache->has_context = true;
    if (! udpconnectorFlushPacketDestinationQueue(t, line, ts, ls, cache))
    {
        lineUnref(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    lineUnref(line);
    udpconnectorPacketDnsRequestDestroy(request);
}

static bool udpconnectorStartPacketDnsResolve(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                              udpconnector_packet_destination_t *cache, uint32_t destination_index)
{
    udpconnector_tstate_t *ts       = tunnelGetState(t);
    address_context_t     *dest_ctx = &cache->dest_ctx;

    if (dest_ctx->domain == NULL || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: packet destination domain or port is not ready");
        return false;
    }

    udpconnector_packet_dns_request_t *request = memoryAllocate(sizeof(*request));
    if (request == NULL)
    {
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "UdpConnector: failed to allocate packet async dns request");
        return false;
    }

    char *domain_copy = stringDuplicate(dest_ctx->domain);
    if (domain_copy == NULL)
    {
        memoryFree(request);
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "UdpConnector: failed to copy packet async dns domain");
        return false;
    }

    *request = (udpconnector_packet_dns_request_t) {
        .tunnel            = t,
        .line              = l,
        .domain            = domain_copy,
        .destination_index = destination_index,
        .strategy          = ts->domain_strategy,
        .cancelled         = false,
        .prev              = NULL,
        .next              = NULL,
    };

    lineRef(l);
    udpconnectorPacketDnsRequestLink(ls, request);
    cache->resolving = true;

    int rc = workerResolveDomainServiceAsync(
        lineGetWID(l), request->domain, NULL, SOCK_DGRAM, udpconnectorOnPacketDnsResolved, request);
    if (rc != ARES_SUCCESS)
    {
        udpconnectorPacketDnsRequestUnlink(ls, request);
        cache->resolving = false;
        lineUnref(l);
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "UdpConnector: failed to start packet async dns resolve for %s: %s",
                    request->domain,
                    ares_strerror(rc));
        udpconnectorPacketDnsRequestDestroy(request);
        return false;
    }

    return true;
}

static void udpconnectorBuildPacketDestinationContext(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                                      uint32_t destination_index, address_context_t *dest_ctx)
{
    udpconnector_tstate_t            *ts                 = tunnelGetState(t);
    address_context_t                *src_ctx            = lineGetSourceAddressContext(l);
    address_context_t                *line_dest_ctx      = lineGetDestinationAddressContext(l);
    const dynamic_value_t            *dest_addr_selected = &ts->dest_addr_selected;
    const dynamic_value_t            *dest_port_selected = &ts->dest_port_selected;
    const address_context_t          *constant_dest_addr = &ts->constant_dest_addr;
    uint16_t                          random_dest_port_x = ts->random_dest_port_x;
    uint16_t                          random_dest_port_y = ts->random_dest_port_y;
    const udpconnector_destination_t *selected_destination =
        ts->destinations_count > 0 ? &ts->destinations[destination_index] : NULL;

    addresscontextCopy(dest_ctx, &ls->packet_base_dest_ctx);

    if (selected_destination != NULL)
    {
        dest_addr_selected = &selected_destination->dest_addr_selected;
        dest_port_selected = &selected_destination->dest_port_selected;
        constant_dest_addr = &selected_destination->constant_dest_addr;
        random_dest_port_x = selected_destination->random_dest_port_x;
        random_dest_port_y = selected_destination->random_dest_port_y;
    }

    address_context_t original_dest_ctx = {0};
    addresscontextCopy(&original_dest_ctx, line_dest_ctx);

    udpconnectorSetupDestinationAddress(dest_addr_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    udpconnectorSetupDestinationPort(dest_port_selected,
                                     constant_dest_addr,
                                     random_dest_port_x,
                                     random_dest_port_y,
                                     dest_ctx,
                                     &original_dest_ctx,
                                     src_ctx);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    addresscontextReset(&original_dest_ctx);
}

static udpconnector_packet_destination_t *udpconnectorSelectPacketDestination(tunnel_t *t, udpconnector_lstate_t *ls,
                                                                              uint32_t *destination_index)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);

    *destination_index = udpconnectorSelectWeightedDestinationIndex(ts);
    assert(ls->packet_destinations != NULL);
    assert(*destination_index < ls->packet_destinations_count);

    return &ls->packet_destinations[*destination_index];
}

static bool udpconnectorPacketContextsSelectSamePeer(const address_context_t *left, const address_context_t *right)
{
    if (left->port != right->port)
    {
        return false;
    }

    const bool left_concrete  = addresscontextCanConvertToSockAddr(left);
    const bool right_concrete = addresscontextCanConvertToSockAddr(right);
    if (left_concrete && right_concrete)
    {
        return ipAddrEqualsExact(&left->ip_address, &right->ip_address);
    }
    if (! left_concrete && right_concrete)
    {
        return false;
    }
    if (left->domain != NULL && left->domain_len > 0 && right->domain != NULL && right->domain_len > 0)
    {
        return stringAsciiCaseEquals(left->domain, right->domain);
    }
    return false;
}

static udpconnector_packet_peer_result_e udpconnectorSelectPacketPeer(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                                                      sbuf_t *buf, sockaddr_u *peer_addr)
{
    udpconnector_tstate_t             *ts = tunnelGetState(t);
    uint32_t                           destination_index;
    udpconnector_packet_destination_t *cache = udpconnectorSelectPacketDestination(t, ls, &destination_index);

    const udpconnector_destination_t *selected_destination =
        ts->destinations_count > 0 ? &ts->destinations[destination_index] : NULL;
    const dynamic_value_t *dest_addr_selected =
        selected_destination != NULL ? &selected_destination->dest_addr_selected : &ts->dest_addr_selected;
    const dynamic_value_t *dest_port_selected =
        selected_destination != NULL ? &selected_destination->dest_port_selected : &ts->dest_port_selected;
    const bool uses_line_context = udpconnectorDestinationUsesLineContext(dest_addr_selected, dest_port_selected);

    if (uses_line_context)
    {
        address_context_t current = {0};
        udpconnectorBuildPacketDestinationContext(t, l, ls, destination_index, &current);

        if (cache->resolving)
        {
            const bool same_peer = udpconnectorPacketContextsSelectSamePeer(&cache->dest_ctx, &current);
            addresscontextReset(&current);
            if (! same_peer)
            {
                /* One destination slot owns one in-flight DNS request. Never
                 * enqueue bytes for a newer mutable context behind the old
                 * request, because its completion would send them to the old
                 * peer. The later datagram is intentionally dropped. */
                lineReuseBuffer(l, buf);
                return kUdpConnectorPacketPeerConsumed;
            }
        }
        else
        {
            if (cache->has_context && udpconnectorPacketContextsSelectSamePeer(&cache->dest_ctx, &current))
            {
                addresscontextReset(&current);
            }
            else
            {
                if (cache->has_context)
                {
                    addresscontextReset(&cache->dest_ctx);
                }
                addresscontextCopy(&cache->dest_ctx, &current);
                addresscontextReset(&current);
                cache->has_context = true;
            }
        }
    }
    else if (! cache->has_context)
    {
        udpconnectorBuildPacketDestinationContext(t, l, ls, destination_index, &cache->dest_ctx);
        cache->has_context = true;
    }

    if (! addresscontextHasPort(&cache->dest_ctx))
    {
        LOGE("UdpConnector: packet destination port is not initialized");
        lineReuseBuffer(l, buf);
        return kUdpConnectorPacketPeerConsumed;
    }

    if (addresscontextIsDomain(&cache->dest_ctx) && ! addresscontextIsDomainResolved(&cache->dest_ctx))
    {
        if (! udpconnectorQueuePacketForDestination(t, l, ts, ls, cache, buf))
        {
            return kUdpConnectorPacketPeerConsumed;
        }

        if (! cache->resolving && ! udpconnectorStartPacketDnsResolve(t, l, ls, cache, destination_index))
        {
            discard udpconnectorPacketDestinationFail(t, l, ls, cache);
        }

        return kUdpConnectorPacketPeerConsumed;
    }

    if (! addresscontextCanConvertToSockAddr(&cache->dest_ctx))
    {
        LOGE("UdpConnector: packet destination address is not initialized");
        lineReuseBuffer(l, buf);
        return kUdpConnectorPacketPeerConsumed;
    }

    *peer_addr = addresscontextToSockAddr(&cache->dest_ctx);
    return kUdpConnectorPacketPeerReady;
}

void udpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);

    if (ls->write_paused)
    {
        handleQueuedWrite(t, l, ts, ls, buf);
        return;
    }

    if (! ls->route_destination_pinned && ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        sockaddr_u peer_addr;

        if (udpconnectorSelectPacketPeer(t, l, ls, buf, &peer_addr) == kUdpConnectorPacketPeerConsumed)
        {
            return;
        }

        udpconnectorWriteToPeer(t, l, ts, ls, buf, &peer_addr);
        return;
    }

    udpconnectorWriteToPeer(t, l, ts, ls, buf, &ls->peer_addr);
}

#if defined(UDPCONNECTOR_POOL_TEST_HOOKS)
bool udpconnectorTestFlushPacketDestinationQueue(tunnel_t *t, line_t *l, uint32_t destination_index)
{
    udpconnector_lstate_t *ls = lineGetState(l, t);
    assert(destination_index < ls->packet_destinations_count);
    return udpconnectorFlushPacketDestinationQueue(
        t, l, tunnelGetState(t), ls, &ls->packet_destinations[destination_index]);
}
#endif
