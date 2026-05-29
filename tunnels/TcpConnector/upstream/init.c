#include "structure.h"

#include "loggers/network_logger.h"

static const tcpconnector_destination_t *selectWeightedDestination(const tcpconnector_tstate_t *ts)
{
    if (ts->destinations_count == 0)
    {
        return NULL;
    }

    assert(ts->destinations_weight_total > 0);

    uint64_t pick       = fastRand64() % ts->destinations_weight_total;
    uint64_t cumulative = 0;

    for (uint32_t i = 0; i < ts->destinations_count; ++i)
    {
        cumulative += ts->destinations[i].weight;
        if (pick < cumulative)
        {
            return &ts->destinations[i];
        }
    }

    return &ts->destinations[ts->destinations_count - 1];
}

static void setupDestinationAddress(const dynamic_value_t *dest_addr_selected, const address_context_t *constant_dest_addr,
                                    address_context_t *dest_ctx, const address_context_t *original_dest_ctx,
                                    address_context_t *src_ctx)
{
    switch ((tcpconnector_strategy_e) dest_addr_selected->status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextAddrCopy(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextAddrCopy(dest_ctx, constant_dest_addr);
        break;
    case kTcpConnectorStrategyFromDest:
        addresscontextAddrCopy(dest_ctx, original_dest_ctx);
        addresscontextSetProtocol(dest_ctx, IPPROTO_TCP);
        break;
    default:
        break;
    }
}

static void setupDestinationPort(const dynamic_value_t *dest_port_selected, const address_context_t *constant_dest_addr,
                                 address_context_t *dest_ctx, const address_context_t *original_dest_ctx,
                                 address_context_t *src_ctx)
{
    switch ((tcpconnector_strategy_e) dest_port_selected->status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextCopyPort(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextCopyPort(dest_ctx, (address_context_t *) constant_dest_addr);
        break;
    case kTcpConnectorStrategyFromDest:
        addresscontextCopyPort(dest_ctx, (address_context_t *) original_dest_ctx);
        break;
    default:
        break;
    }
}

static const char *getSourceBindIp(const tcpconnector_tstate_t *ts, char *interface_ip, size_t interface_ip_len)
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
        LOGE("TcpConnector: could not get interface \"%s\" ip", ts->interface_name);
        return NULL;
    }

    return interface_ip;
}

static bool bindSourceIpIfNeeded(int sockfd, int addr_type, const tcpconnector_tstate_t *ts)
{
    char        interface_ip[INET_ADDRSTRLEN] = {0};
    const char *source_ip = getSourceBindIp(ts, interface_ip, sizeof(interface_ip));

    if (source_ip == NULL)
    {
        if (ts->source_ip == NULL && ts->interface_name != NULL && ! socketOptionBindToDeviceSupported())
        {
            return false;
        }
        return true;
    }

    sockaddr_u local_addr;
    memorySet(&local_addr, 0, sizeof(local_addr));

    if (sockaddrSetIpAddressPort(&local_addr, source_ip, 0) != 0)
    {
        LOGE("TcpConnector: could not prepare source-ip %s", source_ip);
        return false;
    }

    if (local_addr.sa.sa_family != addr_type)
    {
        LOGE("TcpConnector: source-ip address family does not match destination address family");
        return false;
    }

    if (bind(sockfd, &local_addr.sa, sockaddrLen(&local_addr)) < 0)
    {
        LOGE("TcpConnector: bind source-ip failed");
        return false;
    }

    return true;
}

static bool tcpconnectorDnsFamilyAllowedByStrategy(int family, int strategy)
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

static bool tcpconnectorDnsFamilyPreferredByStrategy(int family, int strategy)
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

static const dns_resolved_addr_t *tcpconnectorSelectResolvedAddress(const dns_resolved_addr_t *addrs, size_t naddrs,
                                                                    int strategy)
{
    const dns_resolved_addr_t *fallback = NULL;

    for (size_t i = 0; i < naddrs; ++i)
    {
        if (! tcpconnectorDnsFamilyAllowedByStrategy(addrs[i].family, strategy))
        {
            continue;
        }

        if (fallback == NULL)
        {
            fallback = &addrs[i];
        }

        if (tcpconnectorDnsFamilyPreferredByStrategy(addrs[i].family, strategy))
        {
            return &addrs[i];
        }
    }

    return fallback;
}

static bool tcpconnectorApplyResolvedAddress(address_context_t *dest_ctx, const dns_resolved_addr_t *resolved)
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

static bool tcpconnectorBeginConnect(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls, uint64_t outbound_ip_range)
{
    tcpconnector_tstate_t *ts       = tunnelGetState(t);
    address_context_t    *dest_ctx = &(l->routing_context.dest_ctx);
    int                   sockfd   = -1;

    // apply free bind if needed
    if (outbound_ip_range > 0)
    {
        if (! tcpconnectorApplyFreeBindRandomDestIp(dest_ctx, outbound_ip_range))
        {
            goto fail;
        }
    }

    // sockaddr_set_ipport(&(dest_ctx.addr), "127.0.0.1", 443);

    wloop_t *loop = getWorkerLoop(getWID());

    assert(dest_ctx->ip_address.type == IPADDR_TYPE_V4 || dest_ctx->ip_address.type == IPADDR_TYPE_V6);
    int addr_type = dest_ctx->ip_address.type == IPADDR_TYPE_V4 ? AF_INET : AF_INET6;

    sockfd = (int) socket(addr_type, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        LOGE("TcpConnector: could not create socket");
        goto fail;
    }

    if (ts->option_tcp_no_delay)
    {
        tcpNoDelay(sockfd, 1);
    }

    if (socketOptionBindToDevice(sockfd, ts->interface_name) != 0)
    {
        LOGE("TcpConnector: setsockopt SO_BINDTODEVICE error");
        goto fail;
    }

#ifdef TCP_FASTOPEN
    if (ts->option_tcp_fast_open)
    {
        const int yes = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, (const char *) &yes, sizeof(yes));
    }
#endif

    if (ts->fwmark != kFwMarkInvalid)
    {
        if (socketOptionSetFwMark(sockfd, ts->fwmark) < 0)
        {
            LOGE("TcpConnector: setsockopt SO_MARK error");
            goto fail;
        }
    }

    if (ts->option_reuse_addr && socketOptionReuseAddr(sockfd, 1) != 0)
    {
        LOGE("TcpConnector: set socket reuseaddr failed");
        goto fail;
    }

    if (! bindSourceIpIfNeeded(sockfd, addr_type, ts))
    {
        goto fail;
    }

    wio_t *io = wioGet(loop, sockfd);
    assert(io != NULL);
    sockfd = -1;

    sockaddr_u addr = addresscontextToSockAddr(dest_ctx);

    wioSetPeerAddr(io, (struct sockaddr *) &(addr), (int) sockaddrLen(&(addr)));
    ls->io = io;
    weventSetUserData(io, ls);

    ls->idle_handle = idletableCreateItem(ts->idle_table, tcpconnectorIdleKey(io), ls,
                                          tcpconnectorOnIdleConnectionExpire, lineGetWID(l), kReadWriteTimeoutMs);
    if (UNLIKELY(ls->idle_handle == NULL))
    {
        LOGE("TcpConnector: failed to register idle item for io id:%u FD:%x", wioGetID(io), wioGetFD(io));
        weventSetUserData(io, NULL);
        wioClose(io);
        ls->io = NULL;
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return false;
    }

    wioSetCallBackConnect(io, tcpconnectorOnOutBoundConnected);
    wioSetCallBackClose(io, tcpconnectorOnClose);
    // wioSetReadTimeout(lstate->io, kReadWriteTimeoutMs);

    // issue connect on the socket
    wioConnect(io);

    return true;
fail:
    SAFE_CLOSESOCKET(sockfd);
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
    return false;
}

static void tcpconnectorOnDnsResolved(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                                      size_t naddrs)
{
    tcpconnector_dns_request_t *request = userdata;
    tunnel_t                   *t       = request->tunnel;
    line_t                     *l       = request->line;

    if (request->cancelled || ! lineIsAlive(l))
    {
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    tcpconnector_lstate_t *ls = lineGetState(l, t);

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

    tcpconnector_tstate_t *ts       = tunnelGetState(t);
    address_context_t    *dest_ctx = &(l->routing_context.dest_ctx);

    const char *domain = dest_ctx->domain != NULL ? dest_ctx->domain : "<unknown>";

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        LOGE("TcpConnector: async dns resolve failed for %s: %s", domain,
             error != NULL ? error : ares_strerror(status));
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    const dns_resolved_addr_t *selected = tcpconnectorSelectResolvedAddress(addrs, naddrs, ts->domain_strategy);
    if (! tcpconnectorApplyResolvedAddress(dest_ctx, selected))
    {
        LOGE("TcpConnector: async dns resolve returned no usable address for %s", domain);
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    if (loggerCheckWriteLevel(getNetworkLogger(), (log_level_e) LOG_LEVEL_DEBUG))
    {
        sockaddr_u resolved_addr = addresscontextToSockAddr(dest_ctx);
        char       ip[SOCKADDR_STRLEN];
        LOGD("TcpConnector: %s resolved to %s", domain, SOCKADDR_STR(&resolved_addr, ip));
    }

    uint64_t outbound_ip_range = request->outbound_ip_range;
    memoryFree(request);

    discard tcpconnectorBeginConnect(t, l, ls, outbound_ip_range);
    lineUnlock(l);
}

static bool tcpconnectorStartDnsResolve(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls, uint64_t outbound_ip_range)
{
    address_context_t *dest_ctx = &(l->routing_context.dest_ctx);

    if (dest_ctx->domain == NULL)
    {
        LOGF("TcpConnector: destination address is not set");
        return false;
    }

    tcpconnector_dns_request_t *request = memoryAllocate(sizeof(*request));
    if (request == NULL)
    {
        LOGE("TcpConnector: failed to allocate async dns request");
        return false;
    }

    *request = (tcpconnector_dns_request_t) {
        .tunnel            = t,
        .line              = l,
        .outbound_ip_range = outbound_ip_range,
        .cancelled         = false,
    };

    lineLock(l);
    ls->dns_request = request;
    ls->resolving   = true;

    int rc = workerResolveDomainServiceAsync(lineGetWID(l), dest_ctx->domain, NULL, SOCK_STREAM,
                                             tcpconnectorOnDnsResolved, request);
    if (rc != ARES_SUCCESS)
    {
        tcpconnectorCancelDnsRequest(ls);
        lineUnlock(l);
        memoryFree(request);
        LOGE("TcpConnector: failed to start async dns resolve for %s: %s", dest_ctx->domain, ares_strerror(rc));
        return false;
    }

    return true;
}

void tcpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    tcpconnector_lstate_t *ls = lineGetState(l, t);

    tcpconnectorLinestateInitialize(ls);

    ls->tunnel       = t;
    ls->line         = l;
    ls->write_paused = true;

    // findout how to deal with destination address
    address_context_t *dest_ctx = &(l->routing_context.dest_ctx);
    address_context_t *src_ctx  = &(l->routing_context.src_ctx);
    const dynamic_value_t    *dest_addr_selected = &ts->dest_addr_selected;
    const dynamic_value_t    *dest_port_selected = &ts->dest_port_selected;
    const address_context_t  *constant_dest_addr = &ts->constant_dest_addr;
    uint64_t                  outbound_ip_range  = ts->outbound_ip_range;
    const tcpconnector_destination_t *selected_destination = selectWeightedDestination(ts);

    if (selected_destination != NULL)
    {
        dest_addr_selected = &selected_destination->dest_addr_selected;
        dest_port_selected = &selected_destination->dest_port_selected;
        constant_dest_addr = &selected_destination->constant_dest_addr;
        outbound_ip_range  = selected_destination->outbound_ip_range;
    }

    address_context_t original_dest_ctx = {0};
    addresscontextAddrCopy(&original_dest_ctx, dest_ctx);

    setupDestinationAddress(dest_addr_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    setupDestinationPort(dest_port_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    addresscontextReset(&original_dest_ctx);

    if (! addresscontextHasPort(dest_ctx))
    {
        LOGE("TcpConnector: destination port is not initialized");
        goto fail;
    }

    // Resolve domain name asynchronously if needed. Payloads that arrive before
    // DNS/connect completion keep using the normal pre-connect write queue.
    if (! dest_ctx->type_ip)
    {
        if (! tcpconnectorStartDnsResolve(t, l, ls, outbound_ip_range))
        {
            goto fail;
        }
        return;
    }

    if (! tcpconnectorBeginConnect(t, l, ls, outbound_ip_range))
    {
        return;
    }

    return;
fail:
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
