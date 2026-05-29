#include "structure.h"

#include "loggers/network_logger.h"

typedef enum udpconnector_packet_peer_result_e
{
    kUdpConnectorPacketPeerReady = 0,
    kUdpConnectorPacketPeerConsumed
} udpconnector_packet_peer_result_e;

static void closeLine(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls)
{
    if (ls->io != NULL)
    {
        bool removed = idletableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, udpconnectorIdleKey(ls->io));
        if (! removed)
        {
            LOGF("UdpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
            terminateProgram(1);
        }

        ls->idle_handle = NULL;
        weventSetUserData(ls->io, NULL);
        wioClose(ls->io);
    }

    udpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

static void handleQueueOverflow(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls)
{
    LOGE("UdpConnector: upstream write queue overflow, size: %d, limit: %d",
         (int) udpconnectorQueuedWriteBytes(ls), (int) kUdpMaxPauseQueueSize);

    closeLine(t, l, ts, ls);
}

static void handleQueuedWrite(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls, sbuf_t *buf)
{
    if (! ls->queue_pause_sent && udpconnectorQueuedWriteBytes(ls) > kUdpMinPauseQueueSize)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);
        if (! withLineLocked(l, tunnelPrevDownStreamPause, t))
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
    if (request == NULL)
    {
        return;
    }

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

static bool udpconnectorPayloadSockAddrEquals(const sockaddr_u *lhs, const sockaddr_u *rhs)
{
    if (lhs == NULL || rhs == NULL || lhs->sa.sa_family != rhs->sa.sa_family)
    {
        return false;
    }

    switch (lhs->sa.sa_family)
    {
    case AF_INET:
        return lhs->sin.sin_port == rhs->sin.sin_port && lhs->sin.sin_addr.s_addr == rhs->sin.sin_addr.s_addr;
    case AF_INET6:
        return lhs->sin6.sin6_port == rhs->sin6.sin6_port &&
               memoryCompare(lhs->sin6.sin6_addr.s6_addr, rhs->sin6.sin6_addr.s6_addr,
                             sizeof(lhs->sin6.sin6_addr.s6_addr)) == 0;
    default:
        return false;
    }
}

static bool udpconnectorPeerMatchesSocketFamily(udpconnector_lstate_t *ls, const sockaddr_u *peer_addr)
{
    return ls->io != NULL && wioGetLocaladdrU(ls->io)->sa.sa_family == peer_addr->sa.sa_family;
}

static void udpconnectorWriteToPeer(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls,
                                    sbuf_t *buf, const sockaddr_u *peer_addr)
{
    discard t;

    if (! udpconnectorPeerMatchesSocketFamily(ls, peer_addr))
    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGE("UdpConnector: selected packet destination [%s] is not compatible with this UDP socket family",
             SOCKADDR_STR(peer_addr, peeraddrstr));
        lineReuseBuffer(l, buf);
        return;
    }

    idletableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kUdpKeepExpireTime);

    ls->peer_addr = *peer_addr;
    if (! udpconnectorPayloadSockAddrEquals(wioGetPeerAddrU(ls->io), peer_addr))
    {
        wioSetPeerAddr(ls->io, (struct sockaddr *) &peer_addr->sa, sockaddrLen((sockaddr_u *) peer_addr));
    }

    wioWrite(ls->io, buf);
}

static bool udpconnectorMaybeResumeQueuedSender(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls)
{
    if (! ls->queue_pause_sent || ls->write_paused || ls->resolving || udpconnectorQueuedWriteBytes(ls) > 0)
    {
        return true;
    }

    ls->queue_pause_sent = false;
    return withLineLocked(l, tunnelPrevDownStreamResume, t);
}

static void udpconnectorPacketDestinationDropPending(udpconnector_packet_destination_t *cache)
{
    bufferqueueDestroy(&cache->pending_queue);
    cache->pending_queue = bufferqueueCreate(kUdpPauseQueueCapacity);
}

static bool udpconnectorPacketDestinationFail(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                              udpconnector_packet_destination_t *cache)
{
    cache->resolving = false;
    cache->has_context = false;
    addresscontextReset(&cache->dest_ctx);
    udpconnectorPacketDestinationDropPending(cache);
    return udpconnectorMaybeResumeQueuedSender(t, l, ls);
}

static bool udpconnectorFlushPacketDestinationQueue(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts,
                                                    udpconnector_lstate_t *ls,
                                                    udpconnector_packet_destination_t *cache)
{
    sockaddr_u peer_addr = addresscontextToSockAddr(&cache->dest_ctx);

    while (bufferqueueGetBufCount(&cache->pending_queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&cache->pending_queue);
        udpconnectorWriteToPeer(t, l, ts, ls, buf, &peer_addr);
    }

    return udpconnectorMaybeResumeQueuedSender(t, l, ls);
}

static bool udpconnectorQueuePacketForDestination(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts,
                                                  udpconnector_lstate_t *ls,
                                                  udpconnector_packet_destination_t *cache, sbuf_t *buf)
{
    if (! ls->queue_pause_sent && udpconnectorQueuedWriteBytes(ls) > kUdpMinPauseQueueSize)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);
        if (! withLineLocked(l, tunnelPrevDownStreamPause, t))
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
        lineUnlock(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    tunnel_t                 *t  = request->tunnel;
    udpconnector_lstate_t    *ls = lineGetState(line, t);
    udpconnector_tstate_t    *ts = tunnelGetState(t);
    const dns_resolved_addr_t *selected;

    udpconnectorPacketDnsRequestUnlink(ls, request);

    if (request->destination_index >= ls->packet_destinations_count)
    {
        lineUnlock(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    udpconnector_packet_destination_t *cache = &ls->packet_destinations[request->destination_index];
    cache->resolving = false;

    if (asyncdnsStatusIsShutdown(status))
    {
        discard udpconnectorPacketDestinationFail(t, line, ls, cache);
        lineUnlock(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        LOGE("UdpConnector: async dns resolve failed for %s: %s", request->domain,
             error != NULL ? error : ares_strerror(status));
        if (! udpconnectorPacketDestinationFail(t, line, ls, cache))
        {
            lineUnlock(line);
            udpconnectorPacketDnsRequestDestroy(request);
            return;
        }
        lineUnlock(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    selected = udpconnectorSelectResolvedAddress(addrs, naddrs, request->strategy);
    if (! udpconnectorApplyResolvedAddress(&cache->dest_ctx, selected))
    {
        LOGE("UdpConnector: async dns resolve returned no usable address for %s", request->domain);
        if (! udpconnectorPacketDestinationFail(t, line, ls, cache))
        {
            lineUnlock(line);
            udpconnectorPacketDnsRequestDestroy(request);
            return;
        }
        lineUnlock(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    cache->has_context = true;
    if (! udpconnectorFlushPacketDestinationQueue(t, line, ts, ls, cache))
    {
        lineUnlock(line);
        udpconnectorPacketDnsRequestDestroy(request);
        return;
    }

    lineUnlock(line);
    udpconnectorPacketDnsRequestDestroy(request);
}

static bool udpconnectorStartPacketDnsResolve(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                              udpconnector_packet_destination_t *cache, uint32_t destination_index)
{
    udpconnector_tstate_t *ts       = tunnelGetState(t);
    address_context_t    *dest_ctx = &cache->dest_ctx;

    if (dest_ctx->domain == NULL || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: packet destination domain or port is not ready");
        return false;
    }

    udpconnector_packet_dns_request_t *request = memoryAllocate(sizeof(*request));
    if (request == NULL)
    {
        LOGE("UdpConnector: failed to allocate packet async dns request");
        return false;
    }

    char *domain_copy = stringDuplicate(dest_ctx->domain);
    if (domain_copy == NULL)
    {
        memoryFree(request);
        LOGE("UdpConnector: failed to copy packet async dns domain");
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

    lineLock(l);
    udpconnectorPacketDnsRequestLink(ls, request);
    cache->resolving = true;

    int rc = workerResolveDomainServiceAsync(lineGetWID(l), request->domain, NULL, SOCK_DGRAM,
                                             udpconnectorOnPacketDnsResolved, request);
    if (rc != ARES_SUCCESS)
    {
        udpconnectorPacketDnsRequestUnlink(ls, request);
        cache->resolving = false;
        lineUnlock(l);
        LOGE("UdpConnector: failed to start packet async dns resolve for %s: %s", request->domain, ares_strerror(rc));
        udpconnectorPacketDnsRequestDestroy(request);
        return false;
    }

    return true;
}

static void udpconnectorBuildPacketDestinationContext(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls,
                                                      uint32_t destination_index, address_context_t *dest_ctx)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    address_context_t *src_ctx = lineGetSourceAddressContext(l);
    address_context_t *line_dest_ctx = lineGetDestinationAddressContext(l);
    const dynamic_value_t *dest_addr_selected = &ts->dest_addr_selected;
    const dynamic_value_t *dest_port_selected = &ts->dest_port_selected;
    const address_context_t *constant_dest_addr = &ts->constant_dest_addr;
    uint16_t random_dest_port_x = ts->random_dest_port_x;
    uint16_t random_dest_port_y = ts->random_dest_port_y;
    const udpconnector_destination_t *selected_destination =
        ts->destinations_count > 0 ? &ts->destinations[destination_index] : NULL;

    addresscontextAddrCopy(dest_ctx, &ls->packet_base_dest_ctx);

    if (selected_destination != NULL)
    {
        dest_addr_selected = &selected_destination->dest_addr_selected;
        dest_port_selected = &selected_destination->dest_port_selected;
        constant_dest_addr = &selected_destination->constant_dest_addr;
        random_dest_port_x = selected_destination->random_dest_port_x;
        random_dest_port_y = selected_destination->random_dest_port_y;
    }

    address_context_t original_dest_ctx = {0};
    addresscontextAddrCopy(&original_dest_ctx, line_dest_ctx);

    udpconnectorSetupDestinationAddress(dest_addr_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    udpconnectorSetupDestinationPort(dest_port_selected, constant_dest_addr, random_dest_port_x, random_dest_port_y,
                                     dest_ctx, &original_dest_ctx, src_ctx);
    addresscontextReset(&original_dest_ctx);
}

static udpconnector_packet_destination_t *udpconnectorSelectPacketDestination(tunnel_t *t, udpconnector_lstate_t *ls,
                                                                             uint32_t *destination_index)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);

    *destination_index = udpconnectorSelectWeightedDestinationIndex(ts);
    if (*destination_index >= ls->packet_destinations_count || ls->packet_destinations == NULL)
    {
        return NULL;
    }

    return &ls->packet_destinations[*destination_index];
}

static udpconnector_packet_peer_result_e udpconnectorSelectPacketPeer(tunnel_t *t, line_t *l,
                                                                      udpconnector_lstate_t *ls, sbuf_t *buf,
                                                                      sockaddr_u *peer_addr)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    uint32_t               destination_index;
    udpconnector_packet_destination_t *cache = udpconnectorSelectPacketDestination(t, ls, &destination_index);

    if (cache == NULL)
    {
        LOGE("UdpConnector: packet destination cache is not initialized");
        lineReuseBuffer(l, buf);
        return kUdpConnectorPacketPeerConsumed;
    }

    const udpconnector_destination_t *selected_destination =
        ts->destinations_count > 0 ? &ts->destinations[destination_index] : NULL;
    const dynamic_value_t *dest_addr_selected =
        selected_destination != NULL ? &selected_destination->dest_addr_selected : &ts->dest_addr_selected;
    const dynamic_value_t *dest_port_selected =
        selected_destination != NULL ? &selected_destination->dest_port_selected : &ts->dest_port_selected;
    const bool uses_line_context = udpconnectorDestinationUsesLineContext(dest_addr_selected, dest_port_selected);

    if (uses_line_context && cache->resolving)
    {
        /* Keep the context that owns the in-flight DNS request. */
    }
    else if (! cache->has_context || uses_line_context)
    {
        if (cache->has_context)
        {
            addresscontextReset(&cache->dest_ctx);
        }
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

    wio_t *io = ls->io;
    if (ls->write_paused || ls->resolving || io == NULL)
    {
        handleQueuedWrite(t, l, ts, ls, buf);
        return;
    }

    if (UNLIKELY(wioIsClosed(io)))
    {
        // should not happen in our structure
        LOGF("UdpConnector: UpStream Payload is called on closed wio. This should not happen");
        lineReuseBuffer(l, buf);
        // tunnelPrevDownStreamFinish(t, l);
        assert(false);
        terminateProgram(1);
    }
    // LOGD("writing %d bytes", sbufGetLength(buf));

    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
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
