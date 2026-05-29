#include "structure.h"

#include "loggers/network_logger.h"

uint32_t udpconnectorSelectWeightedDestinationIndex(const udpconnector_tstate_t *ts)
{
    if (ts->destinations_count == 0)
    {
        return 0;
    }

    assert(ts->destinations_weight_total > 0);

    uint64_t pick       = fastRand64() % ts->destinations_weight_total;
    uint64_t cumulative = 0;

    for (uint32_t i = 0; i < ts->destinations_count; ++i)
    {
        cumulative += ts->destinations[i].weight;
        if (pick < cumulative)
        {
            return i;
        }
    }

    return ts->destinations_count - 1;
}

const udpconnector_destination_t *udpconnectorSelectWeightedDestination(const udpconnector_tstate_t *ts)
{
    if (ts->destinations_count == 0)
    {
        return NULL;
    }

    return &ts->destinations[udpconnectorSelectWeightedDestinationIndex(ts)];
}

static const char *getSourceBindIp(const udpconnector_tstate_t *ts, char *interface_ip, size_t interface_ip_len)
{
    if (ts->source_ip != NULL)
    {
        return ts->source_ip;
    }

    if (ts->interface_name == NULL || socketOptionBindToDeviceSupported())
    {
        return NULL;
    }

    if (! getInterfaceIpString(ts->interface_name, interface_ip, interface_ip_len))
    {
        LOGE("UdpConnector: could not get interface \"%s\" ip", ts->interface_name);
        return NULL;
    }

    return interface_ip;
}

static int createAndBindSocket(int family, const udpconnector_tstate_t *ts)
{
    sockaddr_u host_addr = {0};
    char       interface_ip[INET_ADDRSTRLEN] = {0};
    const char *bind_address = getSourceBindIp(ts, interface_ip, sizeof(interface_ip));

    if (family != AF_INET && family != AF_INET6)
    {
        LOGE("UdpConnector: unsupported socket family %d", family);
        return -1;
    }

    if (bind_address == NULL)
    {
        if (ts->source_ip == NULL && ts->interface_name != NULL && ! socketOptionBindToDeviceSupported())
        {
            return -1;
        }
        bind_address = family == AF_INET6 ? "::" : "0.0.0.0";
    }

    if (sockaddrSetIpAddressPort(&host_addr, bind_address, 0) != 0)
    {
        LOGE("UdpConnector: could not prepare bind address %s", bind_address);
        return -1;
    }
    if (host_addr.sa.sa_family != family)
    {
        LOGE("UdpConnector: source-ip address family does not match destination address family");
        return -1;
    }

    int sockfd = socket(family, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LOGE("UdpConnector: socket fd < 0");
        return -1;
    }
    int size   = 4 * 1024 * 1024; // 4MB
    int so_ret = socketOptionSendBuf(sockfd, size);
    if (so_ret != 0)
    {
        LOGE("UdpConnector: set socket send buffer failed, call: setsockopt , value: %d\n", so_ret);
        closesocket(sockfd);
        return -1;
    }
    so_ret = socketOptionRecvBuf(sockfd, size);
    if (so_ret != 0)
    {
        LOGE("UdpConnector: set socket recv buffer failed, call: setsockopt , value: %d\n", so_ret);
        closesocket(sockfd);
        return -1;
    }

    if (socketOptionBindToDevice(sockfd, ts->interface_name) != 0)
    {
        LOGE("UdpConnector: setsockopt SO_BINDTODEVICE error");
        closesocket(sockfd);
        return -1;
    }

    if (ts->fwmark >= 0 && socketOptionSetFwMark(sockfd, ts->fwmark) != 0)
    {
        LOGE("UdpConnector: setsockopt SO_MARK error");
        closesocket(sockfd);
        return -1;
    }

    if (ts->reuse_addr && socketOptionReuseAddr(sockfd, 1) != 0)
    {
        LOGE("UdpConnector: set socket reuseaddr failed");
        closesocket(sockfd);
        return -1;
    }

    if (bind(sockfd, &host_addr.sa, sockaddrLen(&host_addr)) < 0)
    {
        LOGE("UdpConnector: UDP bind failed;");
        closesocket(sockfd);
        return -1;
    }

    return sockfd;
}

void udpconnectorSetupDestinationAddress(const dynamic_value_t *dest_addr_selected,
                                         const address_context_t *constant_dest_addr,
                                         address_context_t *dest_ctx, const address_context_t *original_dest_ctx,
                                         address_context_t *src_ctx)
{
    switch (dest_addr_selected->status)
    {
    case kDvsFromSource:
        addresscontextAddrCopy(dest_ctx, src_ctx);
        break;
    case kDvsConstant:
        addresscontextAddrCopy(dest_ctx, constant_dest_addr);
        break;
    case kDvsFromDest:
        addresscontextAddrCopy(dest_ctx, original_dest_ctx);
        break;
    default:
        break;
    }
}

void udpconnectorSetupDestinationPort(const dynamic_value_t *dest_port_selected,
                                      const address_context_t *constant_dest_addr,
                                      uint16_t random_dest_port_x, uint16_t random_dest_port_y,
                                      address_context_t *dest_ctx, const address_context_t *original_dest_ctx,
                                      address_context_t *src_ctx)
{
    switch (dest_port_selected->status)
    {
    case kDvsFromSource:
        addresscontextCopyPort(dest_ctx, src_ctx);
        break;
    case kDvsConstant:
        addresscontextCopyPort(dest_ctx, (address_context_t *) constant_dest_addr);
        break;
    case kDvsRandom:
        addresscontextSetPort(dest_ctx, (fastRand() % (random_dest_port_y - random_dest_port_x + 1)) +
                                            random_dest_port_x);
        break;
    case kDvsFromDest:
        addresscontextCopyPort(dest_ctx, (address_context_t *) original_dest_ctx);
        break;
    default:
        break;
    }
}

static bool udpconnectorDnsFamilyAllowedByStrategy(int family, int strategy)
{
    switch ((enum domain_strategy) strategy)
    {
    case kDsOnlyIpV4:
        return family == AF_INET;
    case kDsOnlyIpV6:
        return family == AF_INET6;
    default:
        return family == AF_INET || family == AF_INET6;
    }
}

static bool udpconnectorDnsFamilyPreferredByStrategy(int family, int strategy)
{
    switch ((enum domain_strategy) strategy)
    {
    case kDsPreferIpV4:
    case kDsOnlyIpV4:
        return family == AF_INET;
    case kDsPreferIpV6:
    case kDsOnlyIpV6:
        return family == AF_INET6;
    default:
        return true;
    }
}

const dns_resolved_addr_t *udpconnectorSelectResolvedAddress(const dns_resolved_addr_t *addrs, size_t naddrs,
                                                            int strategy)
{
    const dns_resolved_addr_t *fallback = NULL;

    for (size_t i = 0; i < naddrs; ++i)
    {
        if (! udpconnectorDnsFamilyAllowedByStrategy(addrs[i].family, strategy))
        {
            continue;
        }

        if (fallback == NULL)
        {
            fallback = &addrs[i];
        }

        if (udpconnectorDnsFamilyPreferredByStrategy(addrs[i].family, strategy))
        {
            return &addrs[i];
        }
    }

    return fallback;
}

bool udpconnectorApplyResolvedAddress(address_context_t *dest_ctx, const dns_resolved_addr_t *resolved)
{
    if (resolved == NULL || (resolved->family != AF_INET && resolved->family != AF_INET6) ||
        (uintmax_t) resolved->addrlen > (uintmax_t) sizeof(sockaddr_u))
    {
        return false;
    }

    sockaddr_u resolved_addr;
    memoryZero(&resolved_addr, sizeof(resolved_addr));
    memoryCopy(&resolved_addr, &resolved->addr, (size_t) resolved->addrlen);

    if (! sockaddrToIpAddr(&resolved_addr, &dest_ctx->ip_address))
    {
        return false;
    }

    dest_ctx->type_ip         = kCCTypeIp;
    dest_ctx->domain_resolved = true;
    return true;
}

static void udpconnectorSeedPacketDestinationCache(udpconnector_tstate_t *ts, udpconnector_lstate_t *ls,
                                                   const address_context_t *dest_ctx)
{
    if (ts->balance_mode != kUdpConnectorBalanceModePacket || ls->packet_destinations == NULL ||
        ls->packet_initial_destination_index >= ls->packet_destinations_count)
    {
        return;
    }

    udpconnector_packet_destination_t *cache = &ls->packet_destinations[ls->packet_initial_destination_index];
    if (! cache->has_context)
    {
        addresscontextAddrCopy(&cache->dest_ctx, dest_ctx);
        cache->has_context = true;
    }
}

static bool udpconnectorBeginSocket(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls)
{
    udpconnector_tstate_t *ts       = tunnelGetState(t);
    address_context_t    *dest_ctx = lineGetDestinationAddressContext(l);

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: destination address or port is not initialized");
        goto fail;
    }

    sockaddr_u addr   = addresscontextToSockAddr(dest_ctx);
    int        family = addr.sa.sa_family;

    int sockfd = createAndBindSocket(family, ts);
    if (sockfd < 0)
    {
        goto fail;
    }

    wloop_t *loop = getWorkerLoop(getWID());
    wio_t   *io   = wioGet(loop, sockfd);

    ls->io        = io;
    ls->peer_addr = addr;
    udpconnectorSeedPacketDestinationCache(ts, ls, dest_ctx);
    weventSetUserData(io, ls);

    ls->idle_handle =
        idletableCreateItem(ts->idle_table, udpconnectorIdleKey(io), ls, udpconnectorOnIdleConnectionExpire,
                            lineGetWID(l), kUdpInitExpireTime);
    if (UNLIKELY(ls->idle_handle == NULL))
    {
        LOGE("UdpConnector: failed to register idle item for io id:%u FD:%x", wioGetID(io), wioGetFD(io));
        weventSetUserData(io, NULL);
        ls->io = NULL;
        wioClose(io);
        udpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return false;
    }

    wioSetCallBackClose(io, udpconnectorOnClose);
    wioSetCallBackRead(io, udpconnectorOnRecvFrom);
    wioSetPeerAddr(ls->io, &addr.sa, sockaddrLen(&addr));

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGD("UdpConnector: Communication begin FD:%x [%s] => [%s]", wioGetFD(io),
             SOCKADDR_STR(wioGetLocaladdr(io), localaddrstr), SOCKADDR_STR(wioGetPeerAddr(io), peeraddrstr));
    }

    if (! ls->read_paused)
    {
        wioRead(io);
    }

    const bool resume_prev = ls->queue_pause_sent;
    ls->write_paused      = false;

    lineLock(l);
    bool alive = true;
    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        alive = udpconnectorReplayWriteQueue(ls);
    }
    else
    {
        udpconnectorFlushWriteQueue(ls);
    }

    if (alive && resume_prev && udpconnectorQueuedWriteBytes(ls) == 0 && ! ls->write_paused && ! ls->resolving)
    {
        ls->queue_pause_sent = false;
        tunnelPrevDownStreamResume(t, l);
        alive = lineIsAlive(l);
    }
    lineUnlock(l);

    if (! alive)
    {
        return false;
    }

    return true;

fail:
    udpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
    return false;
}

static void udpconnectorOnDnsResolved(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                                      size_t naddrs)
{
    udpconnector_dns_request_t *request = userdata;
    tunnel_t                   *t       = request->tunnel;
    line_t                     *l       = request->line;

    if (request->cancelled || ! lineIsAlive(l))
    {
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    udpconnector_lstate_t *ls = lineGetState(l, t);

    if (ls->dns_request != request || ! ls->resolving)
    {
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    ls->dns_request = NULL;
    ls->resolving   = false;

    if (asyncdnsStatusIsShutdown(status))
    {
        /*
         * Resolver shutdown is not a tunnel close path, but live line state was
         * still pointing at this request. Detach before freeing it so a later
         * line-state destroy will not cancel through stale userdata.
         */
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    udpconnector_tstate_t *ts       = tunnelGetState(t);
    address_context_t    *dest_ctx = lineGetDestinationAddressContext(l);

    const char *domain = dest_ctx->domain != NULL ? dest_ctx->domain : "<unknown>";

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        LOGE("UdpConnector: async dns resolve failed for %s: %s", domain,
             error != NULL ? error : ares_strerror(status));
        udpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    const dns_resolved_addr_t *selected = udpconnectorSelectResolvedAddress(addrs, naddrs, ts->domain_strategy);
    if (! udpconnectorApplyResolvedAddress(dest_ctx, selected))
    {
        LOGE("UdpConnector: async dns resolve returned no usable address for %s", domain);
        udpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    if (loggerCheckWriteLevel(getNetworkLogger(), (log_level_e) LOG_LEVEL_DEBUG))
    {
        sockaddr_u resolved_addr = addresscontextToSockAddr(dest_ctx);
        char       ip[SOCKADDR_STRLEN];
        LOGD("UdpConnector: %s resolved to %s", domain, SOCKADDR_STR(&resolved_addr, ip));
    }

    memoryFree(request);

    discard udpconnectorBeginSocket(t, l, ls);
    lineUnlock(l);
}

static bool udpconnectorStartDnsResolve(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls)
{
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);

    if (dest_ctx->domain == NULL)
    {
        LOGF("UdpConnector: destination address is not set");
        return false;
    }

    udpconnector_dns_request_t *request = memoryAllocate(sizeof(*request));
    if (request == NULL)
    {
        LOGE("UdpConnector: failed to allocate async dns request");
        return false;
    }

    *request = (udpconnector_dns_request_t) {
        .tunnel    = t,
        .line      = l,
        .cancelled = false,
    };

    lineLock(l);
    ls->dns_request  = request;
    ls->resolving    = true;
    ls->write_paused = true;

    int rc = workerResolveDomainServiceAsync(lineGetWID(l), dest_ctx->domain, NULL, SOCK_DGRAM,
                                             udpconnectorOnDnsResolved, request);
    if (rc != ARES_SUCCESS)
    {
        udpconnectorCancelDnsRequest(ls);
        lineUnlock(l);
        memoryFree(request);
        LOGE("UdpConnector: failed to start async dns resolve for %s: %s", dest_ctx->domain, ares_strerror(rc));
        return false;
    }

    return true;
}

void udpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);
    address_context_t     *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t     *src_ctx  = lineGetSourceAddressContext(l);
    const dynamic_value_t *dest_addr_selected = &ts->dest_addr_selected;
    const dynamic_value_t *dest_port_selected = &ts->dest_port_selected;
    const address_context_t *constant_dest_addr = &ts->constant_dest_addr;
    uint16_t random_dest_port_x = ts->random_dest_port_x;
    uint16_t random_dest_port_y = ts->random_dest_port_y;
    uint32_t selected_destination_index = udpconnectorSelectWeightedDestinationIndex(ts);
    const udpconnector_destination_t *selected_destination =
        ts->destinations_count > 0 ? &ts->destinations[selected_destination_index] : NULL;

    udpconnectorLinestateInitialize(ls, t, l, NULL);
    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        addresscontextAddrCopy(&ls->packet_base_dest_ctx, dest_ctx);
        ls->packet_initial_destination_index = selected_destination_index;
    }

    if (selected_destination != NULL)
    {
        dest_addr_selected = &selected_destination->dest_addr_selected;
        dest_port_selected = &selected_destination->dest_port_selected;
        constant_dest_addr = &selected_destination->constant_dest_addr;
        random_dest_port_x = selected_destination->random_dest_port_x;
        random_dest_port_y = selected_destination->random_dest_port_y;
    }

    address_context_t original_dest_ctx = {0};
    addresscontextAddrCopy(&original_dest_ctx, dest_ctx);

    udpconnectorSetupDestinationAddress(dest_addr_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    udpconnectorSetupDestinationPort(dest_port_selected, constant_dest_addr, random_dest_port_x, random_dest_port_y,
                                     dest_ctx, &original_dest_ctx, src_ctx);
    addresscontextReset(&original_dest_ctx);

    if (! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: destination port is not initialized");
        goto fail;
    }

    if (addresscontextIsDomain(dest_ctx) && ! addresscontextIsDomainResolved(dest_ctx))
    {
        if (! udpconnectorStartDnsResolve(t, l, ls))
        {
            goto fail;
        }
        return;
    }

    if (! udpconnectorBeginSocket(t, l, ls))
    {
        return;
    }

    return;

fail:
    udpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
