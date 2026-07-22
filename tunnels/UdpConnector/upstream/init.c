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
    sockaddr_u  host_addr                     = {0};
    char        interface_ip[INET_ADDRSTRLEN] = {0};
    const char *bind_address                  = getSourceBindIp(ts, interface_ip, sizeof(interface_ip));

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
    if (! socketOptionApplySendBuffer(sockfd, ts->send_buffer_size))
    {
        LOGE("UdpConnector: set socket send buffer failed");
        closesocket(sockfd);
        return -1;
    }
    if (! socketOptionApplyRecvBuffer(sockfd, ts->recv_buffer_size))
    {
        LOGE("UdpConnector: set socket recv buffer failed");
        closesocket(sockfd);
        return -1;
    }

    if (socketOptionBindToDevice(sockfd, ts->interface_name) != 0)
    {
        LOGE("UdpConnector: setsockopt SO_BINDTODEVICE error");
        closesocket(sockfd);
        return -1;
    }

    if (egressPinApply(sockfd, family, ts->interface_name) != 0)
    {
        LOGE("UdpConnector: egress pin failed");
        closesocket(sockfd);
        return -1;
    }

    if (ts->fwmark >= 0 && socketOptionSetFwMark(sockfd, ts->fwmark) != 0)
    {
        LOGE("UdpConnector: setsockopt SO_MARK error");
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

void udpconnectorSetupDestinationAddress(const dynamic_value_t   *dest_addr_selected,
                                         const address_context_t *constant_dest_addr, address_context_t *dest_ctx,
                                         const address_context_t *original_dest_ctx, address_context_t *src_ctx)
{
    switch (dest_addr_selected->status)
    {
    case kDvsFromSource:
        addresscontextCopy(dest_ctx, src_ctx);
        break;
    case kDvsConstant:
        addresscontextCopy(dest_ctx, constant_dest_addr);
        break;
    case kDvsFromDest:
        addresscontextCopy(dest_ctx, original_dest_ctx);
        break;
    default:
        break;
    }
}

void udpconnectorSetupDestinationPort(const dynamic_value_t   *dest_port_selected,
                                      const address_context_t *constant_dest_addr, uint16_t random_dest_port_x,
                                      uint16_t random_dest_port_y, address_context_t *dest_ctx,
                                      const address_context_t *original_dest_ctx, address_context_t *src_ctx)
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
        addresscontextSetPort(dest_ctx,
                              (fastRand() % (random_dest_port_y - random_dest_port_x + 1)) + random_dest_port_x);
        break;
    case kDvsFromDest:
        addresscontextCopyPort(dest_ctx, (address_context_t *) original_dest_ctx);
        break;
    default:
        break;
    }
}

const dns_resolved_addr_t *udpconnectorSelectResolvedAddress(const dns_resolved_addr_t *addrs, size_t naddrs,
                                                             int strategy)
{
    return dnsstrategySelectResolvedAddress(addrs, naddrs, (enum domain_strategy) strategy);
}

bool udpconnectorApplyResolvedAddress(address_context_t *dest_ctx, const dns_resolved_addr_t *resolved)
{
    return dnsstrategyApplyResolvedAddress(dest_ctx, resolved);
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
        addresscontextCopy(&cache->dest_ctx, dest_ctx);
        cache->has_context = true;
    }
}

static bool udpconnectorBeginSocket(tunnel_t *t, line_t *l, udpconnector_lstate_t *ls)
{
    udpconnector_tstate_t *ts       = tunnelGetState(t);
    address_context_t     *dest_ctx = lineGetDestinationAddressContext(l);

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
    if (UNLIKELY(wioIsClosed(io)))
    {
        // socket init rejected the fd and already closed it
        goto fail;
    }

    ls->io        = io;
    ls->peer_addr = addr;
    udpconnectorSeedPacketDestinationCache(ts, ls, dest_ctx);
    weventSetUserData(io, ls);

    ls->idle_handle = localidletableCreateItem(udpconnectorGetLineIdleTable(ts, l),
                                               udpconnectorIdleKey(io),
                                               ls,
                                               udpconnectorOnIdleConnectionExpire,
                                               kUdpInitExpireTime);
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

        LOGD("UdpConnector: Communication begin FD:%x [%s] => [%s]",
             wioGetFD(io),
             SOCKADDR_STR(wioGetLocaladdr(io), localaddrstr),
             SOCKADDR_STR(wioGetPeerAddr(io), peeraddrstr));
    }

    if (! ls->read_paused)
    {
        wioRead(io);
    }

    const bool resume_prev = ls->queue_pause_sent;
    ls->write_paused       = false;

    lineLock(l);
    bool alive = true;
    if (! ls->established)
    {
        ls->established = true;
        tunnelPrevDownStreamEst(t, l);
        alive = lineIsAlive(l);
    }

    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        if (alive)
        {
            alive = udpconnectorReplayWriteQueue(ls);
        }
    }
    else if (alive)
    {
        udpconnectorFlushWriteQueue(ls);
    }

    if (alive && resume_prev && udpconnectorQueuedWriteBytes(ls) == 0 && ! ls->write_paused)
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

bool udpconnectorDomainResolverPrepare(tunnel_t *resolver, tunnel_t *connector, line_t *l,
                                       domainresolver_direction_t direction, void *user_lstate)
{
    discard resolver;
    discard direction;

    udpconnector_tstate_t                 *ts                 = tunnelGetState(connector);
    udpconnector_domain_resolver_lstate_t *ls                 = user_lstate;
    address_context_t                     *dest_ctx           = lineGetDestinationAddressContext(l);
    address_context_t                     *src_ctx            = lineGetSourceAddressContext(l);
    const dynamic_value_t                 *dest_addr_selected = &ts->dest_addr_selected;
    const dynamic_value_t                 *dest_port_selected = &ts->dest_port_selected;
    const address_context_t               *constant_dest_addr = &ts->constant_dest_addr;
    uint16_t                               random_dest_port_x = ts->random_dest_port_x;
    uint16_t                               random_dest_port_y = ts->random_dest_port_y;
    uint32_t selected_destination_index = udpconnectorSelectWeightedDestinationIndex(ts);
    const udpconnector_destination_t *selected_destination =
        ts->destinations_count > 0 ? &ts->destinations[selected_destination_index] : NULL;

    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        addresscontextCopy(&ls->packet_base_dest_ctx, dest_ctx);
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
    addresscontextCopy(&original_dest_ctx, dest_ctx);

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

    if (! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: destination port is not initialized");
        return false;
    }

    addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);

    return true;
}

void udpconnectorDomainResolverUserStateDestroy(tunnel_t *resolver, tunnel_t *connector, line_t *l, void *user_lstate)
{
    discard resolver;
    discard connector;
    discard l;

    udpconnector_domain_resolver_lstate_t *ls = user_lstate;
    addresscontextReset(&ls->packet_base_dest_ctx);
}

void udpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpconnector_tstate_t                 *ts       = tunnelGetState(t);
    udpconnector_lstate_t                 *ls       = lineGetState(l, t);
    udpconnector_domain_resolver_lstate_t *resolver_ls =
        domainresolverTunnelGetUserLineState(ts->domain_resolver_tunnel, l);
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);

    udpconnectorLinestateInitialize(ls, t, l, NULL);
    if (UNLIKELY(resolver_ls == NULL))
    {
        LOGF("UdpConnector: internal DomainResolver prepare state is missing");
        terminateProgram(1);
    }

    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        addresscontextCopy(&ls->packet_base_dest_ctx, &resolver_ls->packet_base_dest_ctx);
        ls->packet_initial_destination_index = resolver_ls->packet_initial_destination_index;
    }

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("UdpConnector: destination address or port is not initialized");
        goto fail;
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
