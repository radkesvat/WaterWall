#include "structure.h"

#include "loggers/network_logger.h"

static bool destinationIsHealthy(const tcpconnector_tstate_t *ts, uint32_t index)
{
    return ts->destination_stats == NULL || index >= ts->destinations_count ||
           atomicLoadRelaxed(&ts->destination_stats[index].healthy) != 0;
}

static uint32_t countHealthyDestinations(const tcpconnector_tstate_t *ts)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < ts->destinations_count; ++i)
    {
        if (destinationIsHealthy(ts, i))
        {
            ++count;
        }
    }

    return count;
}

static uint32_t selectWeightedDestinationIndex(const tcpconnector_tstate_t *ts, bool require_healthy)
{
    if (ts->destinations_count == 0)
    {
        return kTcpConnectorNoDestinationIndex;
    }

    uint64_t total_weight = 0;
    for (uint32_t i = 0; i < ts->destinations_count; ++i)
    {
        if (! require_healthy || destinationIsHealthy(ts, i))
        {
            total_weight += ts->destinations[i].weight;
        }
    }

    if (total_weight == 0)
    {
        total_weight = ts->destinations_weight_total;
        require_healthy = false;
    }

    assert(total_weight > 0);

    uint64_t pick       = fastRand64() % total_weight;
    uint64_t cumulative = 0;

    for (uint32_t i = 0; i < ts->destinations_count; ++i)
    {
        if (require_healthy && ! destinationIsHealthy(ts, i))
        {
            continue;
        }

        cumulative += ts->destinations[i].weight;
        if (pick < cumulative)
        {
            return i;
        }
    }

    return ts->destinations_count - 1;
}

static uint32_t selectRoundRobinDestinationIndex(tcpconnector_tstate_t *ts, bool require_healthy)
{
    if (ts->destinations_count == 0)
    {
        return kTcpConnectorNoDestinationIndex;
    }

    uint32_t start = (uint32_t) atomic_fetch_add(&ts->destination_round_index, 1);

    for (uint32_t offset = 0; offset < ts->destinations_count; ++offset)
    {
        uint32_t index = (start + offset) % ts->destinations_count;
        if (! require_healthy || destinationIsHealthy(ts, index))
        {
            return index;
        }
    }

    return start % ts->destinations_count;
}

static uint32_t selectLeastRttDestinationIndex(tcpconnector_tstate_t *ts)
{
    bool require_healthy = countHealthyDestinations(ts) > 0;
    uint32_t start       = (uint32_t) atomic_fetch_add(&ts->destination_round_index, 1);
    uint32_t best_index  = start % ts->destinations_count;
    uint32_t best_rtt    = kTcpConnectorUnknownRttMs;
    bool     found       = false;

    for (uint32_t offset = 0; offset < ts->destinations_count; ++offset)
    {
        uint32_t index = (start + offset) % ts->destinations_count;
        if (require_healthy && ! destinationIsHealthy(ts, index))
        {
            continue;
        }

        uint32_t rtt = ts->destination_stats != NULL
                           ? (uint32_t) atomicLoadRelaxed(&ts->destination_stats[index].rtt_ema_ms)
                           : kTcpConnectorUnknownRttMs;
        if (rtt == kTcpConnectorUnknownRttMs)
        {
            continue;
        }

        if (! found || rtt < best_rtt)
        {
            best_index = index;
            best_rtt   = rtt;
            found      = true;
        }
    }

    return found ? best_index : selectRoundRobinDestinationIndex(ts, require_healthy);
}

static uint32_t selectDestinationIndex(tcpconnector_tstate_t *ts)
{
    if (ts->destinations_count == 0)
    {
        return kTcpConnectorNoDestinationIndex;
    }

    switch (ts->address_selection)
    {
    case kTcpConnectorAddressSelectionFixed:
        return 0;
    case kTcpConnectorAddressSelectionRoundRobin:
        return selectRoundRobinDestinationIndex(ts, false);
    case kTcpConnectorAddressSelectionRandom:
        return (uint32_t) (fastRand64() % ts->destinations_count);
    case kTcpConnectorAddressSelectionHealthyOnly:
        return selectRoundRobinDestinationIndex(ts, countHealthyDestinations(ts) > 0);
    case kTcpConnectorAddressSelectionLeastRtt:
        return selectLeastRttDestinationIndex(ts);
    case kTcpConnectorAddressSelectionRace:
        return selectRoundRobinDestinationIndex(ts, countHealthyDestinations(ts) > 0);
    case kTcpConnectorAddressSelectionWeightedRandom:
    default:
        return selectWeightedDestinationIndex(ts, false);
    }
}

static tcpconnector_socket_options_t getRootSocketOptions(const tcpconnector_tstate_t *ts)
{
    return (tcpconnector_socket_options_t) {
        .option_tcp_no_delay  = ts->option_tcp_no_delay,
        .option_tcp_fast_open = ts->option_tcp_fast_open,
        .option_reuse_addr    = ts->option_reuse_addr,
        .domain_strategy      = ts->domain_strategy,
        .fwmark               = ts->fwmark,
        .send_buffer_size     = ts->send_buffer_size,
        .recv_buffer_size     = ts->recv_buffer_size,
        .interface_name       = ts->interface_name,
        .source_ip            = ts->source_ip,
    };
}

static tcpconnector_socket_options_t getDestinationSocketOptions(const tcpconnector_destination_t *destination)
{
    return (tcpconnector_socket_options_t) {
        .option_tcp_no_delay  = destination->option_tcp_no_delay,
        .option_tcp_fast_open = destination->option_tcp_fast_open,
        .option_reuse_addr    = destination->option_reuse_addr,
        .domain_strategy      = destination->domain_strategy,
        .fwmark               = destination->fwmark,
        .send_buffer_size     = destination->send_buffer_size,
        .recv_buffer_size     = destination->recv_buffer_size,
        .interface_name       = destination->interface_name,
        .source_ip            = destination->source_ip,
    };
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

static const char *getSourceBindIp(const tcpconnector_socket_options_t *socket_options, char *interface_ip,
                                   size_t interface_ip_len)
{
    if (socket_options->source_ip != NULL)
    {
        return socket_options->source_ip;
    }

    if (socket_options->interface_name == NULL || socketOptionBindToDeviceSupported())
    {
        return NULL;
    }

    if (! getInterfaceIpString(socket_options->interface_name, interface_ip, interface_ip_len))
    {
        LOGE("TcpConnector: could not get interface \"%s\" ip", socket_options->interface_name);
        return NULL;
    }

    return interface_ip;
}

static bool bindSourceIpIfNeeded(int sockfd, int addr_type, const tcpconnector_socket_options_t *socket_options)
{
    char        interface_ip[INET_ADDRSTRLEN] = {0};
    const char *source_ip = getSourceBindIp(socket_options, interface_ip, sizeof(interface_ip));

    if (source_ip == NULL)
    {
        if (socket_options->source_ip == NULL && socket_options->interface_name != NULL &&
            ! socketOptionBindToDeviceSupported())
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

static void tcpconnectorProbeAttemptFree(tcpconnector_probe_attempt_t *attempt)
{
    if (attempt == NULL)
    {
        return;
    }

    addresscontextReset(&attempt->dest_ctx);
    memoryFree(attempt);
}

static void tcpconnectorProbeAttemptRemove(tcpconnector_probe_attempt_t *attempt)
{
    if (attempt == NULL || attempt->tunnel == NULL)
    {
        return;
    }

    tcpconnector_tstate_t *ts = tunnelGetState(attempt->tunnel);
    mutexLock(&ts->probe_mutex);

    if (attempt->prev != NULL)
    {
        attempt->prev->next = attempt->next;
    }
    else if (ts->probe_attempts == attempt)
    {
        ts->probe_attempts = attempt->next;
    }

    if (attempt->next != NULL)
    {
        attempt->next->prev = attempt->prev;
    }

    attempt->prev = NULL;
    attempt->next = NULL;
    mutexUnlock(&ts->probe_mutex);
}

static void tcpconnectorProbeAttemptAdd(tunnel_t *t, tcpconnector_probe_attempt_t *attempt)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    mutexLock(&ts->probe_mutex);
    attempt->tunnel = t;
    attempt->prev   = NULL;
    attempt->next   = ts->probe_attempts;

    if (ts->probe_attempts != NULL)
    {
        ts->probe_attempts->prev = attempt;
    }
    ts->probe_attempts = attempt;
    mutexUnlock(&ts->probe_mutex);
}

static bool tcpconnectorProbeAlreadyActive(tunnel_t *t, uint32_t destination_index)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    mutexLock(&ts->probe_mutex);
    for (tcpconnector_probe_attempt_t *attempt = ts->probe_attempts; attempt != NULL; attempt = attempt->next)
    {
        if (attempt->destination_index == destination_index)
        {
            mutexUnlock(&ts->probe_mutex);
            return true;
        }
    }
    mutexUnlock(&ts->probe_mutex);
    return false;
}

static void tcpconnectorProbeOnClose(wio_t *io)
{
    tcpconnector_probe_attempt_t *attempt = weventGetUserdata(io);
    if (attempt == NULL)
    {
        return;
    }

    weventSetUserData(io, NULL);
    attempt->io = NULL;

    if (! attempt->cancelled)
    {
        tcpconnectorRecordDestinationFailure(attempt->tunnel, attempt->destination_index);
    }

    tcpconnectorProbeAttemptRemove(attempt);
    tcpconnectorProbeAttemptFree(attempt);
}

static void tcpconnectorProbeOnConnected(wio_t *io)
{
    tcpconnector_probe_attempt_t *attempt = weventGetUserdata(io);
    if (attempt == NULL)
    {
        return;
    }

    uint64_t now_ms = getTimeOfDayMS();
    uint32_t rtt_ms = 0;
    if (attempt->start_ms > 0 && now_ms >= attempt->start_ms)
    {
        rtt_ms = (uint32_t) (now_ms - attempt->start_ms);
    }

    tcpconnectorRecordDestinationSuccess(attempt->tunnel, attempt->destination_index, rtt_ms);
    tcpconnectorProbeAttemptRemove(attempt);

    weventSetUserData(io, NULL);
    attempt->io = NULL;
    wioClose(io);
    tcpconnectorProbeAttemptFree(attempt);
}

static bool tcpconnectorStartProbeAttempt(tunnel_t *t, uint32_t destination_index)
{
    tcpconnector_tstate_t       *ts          = tunnelGetState(t);
    tcpconnector_destination_t  *destination = &ts->destinations[destination_index];
    tcpconnector_socket_options_t socket_options = getDestinationSocketOptions(destination);

    if (tcpconnectorProbeAlreadyActive(t, destination_index))
    {
        return false;
    }

    if (destination->dest_addr_selected.status != kTcpConnectorStrategyConstant ||
        ! destination->constant_dest_addr.type_ip ||
        ! addresscontextHasPort(&destination->constant_dest_addr))
    {
        return false;
    }

    tcpconnector_probe_attempt_t *attempt = memoryAllocateZero(sizeof(*attempt));
    if (attempt == NULL)
    {
        return false;
    }

    attempt->destination_index = destination_index;
    attempt->outbound_ip_range = destination->outbound_ip_range;
    addresscontextAddrCopy(&attempt->dest_ctx, &destination->constant_dest_addr);

    if (attempt->outbound_ip_range > 0 &&
        ! tcpconnectorApplyFreeBindRandomDestIp(&attempt->dest_ctx, attempt->outbound_ip_range))
    {
        tcpconnectorProbeAttemptFree(attempt);
        return false;
    }

    wloop_t *loop      = getWorkerLoop(getWID());
    int      addr_type = attempt->dest_ctx.ip_address.type == IPADDR_TYPE_V4 ? AF_INET : AF_INET6;
    int      sockfd    = (int) socket(addr_type, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        tcpconnectorProbeAttemptFree(attempt);
        return false;
    }

    if (socket_options.option_tcp_no_delay)
    {
        tcpNoDelay(sockfd, 1);
    }
    if (! socketOptionApplySendBuffer(sockfd, socket_options.send_buffer_size) ||
        ! socketOptionApplyRecvBuffer(sockfd, socket_options.recv_buffer_size) ||
        socketOptionBindToDevice(sockfd, socket_options.interface_name) != 0 ||
        (socket_options.fwmark != kFwMarkInvalid && socketOptionSetFwMark(sockfd, socket_options.fwmark) < 0) ||
        (socket_options.option_reuse_addr && socketOptionReuseAddr(sockfd, 1) != 0) ||
        ! bindSourceIpIfNeeded(sockfd, addr_type, &socket_options))
    {
        SAFE_CLOSESOCKET(sockfd);
        tcpconnectorProbeAttemptFree(attempt);
        return false;
    }

    wio_t *io = wioGet(loop, sockfd);
    assert(io != NULL);
    sockfd = -1;

    sockaddr_u addr = addresscontextToSockAddr(&attempt->dest_ctx);
    wioSetPeerAddr(io, (struct sockaddr *) &addr, (int) sockaddrLen(&addr));
    wioSetCallBackConnect(io, tcpconnectorProbeOnConnected);
    wioSetCallBackClose(io, tcpconnectorProbeOnClose);
    wioSetConnectTimeout(io, (int) ts->address_probe_timeout_ms);
    weventSetUserData(io, attempt);

    attempt->io       = io;
    attempt->start_ms = getTimeOfDayMS();
    tcpconnectorProbeAttemptAdd(t, attempt);
    if (wioConnect(io) != 0)
    {
        tcpconnectorProbeAttemptRemove(attempt);
        weventSetUserData(io, NULL);
        wioClose(io);
        attempt->io = NULL;
        tcpconnectorRecordDestinationFailure(t, destination_index);
        tcpconnectorProbeAttemptFree(attempt);
        return false;
    }
    return true;
}

void tcpconnectorCancelActiveProbes(tunnel_t *t)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    for (;;)
    {
        mutexLock(&ts->probe_mutex);
        if (ts->probe_attempts == NULL)
        {
            mutexUnlock(&ts->probe_mutex);
            break;
        }

        tcpconnector_probe_attempt_t *attempt = ts->probe_attempts;
        if (attempt->next != NULL)
        {
            attempt->next->prev = NULL;
        }
        ts->probe_attempts = attempt->next;
        attempt->prev      = NULL;
        attempt->next      = NULL;

        attempt->cancelled = true;
        wio_t *io = attempt->io;
        attempt->io = NULL;
        if (io != NULL)
        {
            weventSetUserData(io, NULL);
        }
        mutexUnlock(&ts->probe_mutex);

        if (io != NULL)
        {
            wioClose(io);
        }

        tcpconnectorProbeAttemptFree(attempt);
    }
}

void tcpconnectorProbeTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL)
    {
        return;
    }

    tcpconnector_tstate_t *ts = tunnelGetState(t);
    for (uint32_t i = 0; i < ts->destinations_count; ++i)
    {
        discard tcpconnectorStartProbeAttempt(t, i);
    }
}

static void tcpconnectorRemoveIdleHandleOnConnectFailure(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls,
                                                         wio_t *io)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    if (ls->idle_handle == NULL)
    {
        return;
    }

    bool removed = idletableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, tcpconnectorIdleKey(io));
    if (! removed)
    {
        LOGF("TcpConnector: failed to remove idle item for FD:%x ", wioGetFD(io));
        terminateProgram(1);
    }
    ls->idle_handle = NULL;
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

static bool tcpconnectorBeginConnect(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls, uint64_t outbound_ip_range,
                                     const tcpconnector_socket_options_t *socket_options)
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

    if (socket_options->option_tcp_no_delay)
    {
        tcpNoDelay(sockfd, 1);
    }

    if (! socketOptionApplySendBuffer(sockfd, socket_options->send_buffer_size))
    {
        LOGE("TcpConnector: set socket send buffer failed");
        goto fail;
    }

    if (! socketOptionApplyRecvBuffer(sockfd, socket_options->recv_buffer_size))
    {
        LOGE("TcpConnector: set socket recv buffer failed");
        goto fail;
    }

    if (socketOptionBindToDevice(sockfd, socket_options->interface_name) != 0)
    {
        LOGE("TcpConnector: setsockopt SO_BINDTODEVICE error");
        goto fail;
    }

#ifdef TCP_FASTOPEN
    if (socket_options->option_tcp_fast_open)
    {
        const int yes = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, (const char *) &yes, sizeof(yes));
    }
#endif

    if (socket_options->fwmark != kFwMarkInvalid)
    {
        if (socketOptionSetFwMark(sockfd, socket_options->fwmark) < 0)
        {
            LOGE("TcpConnector: setsockopt SO_MARK error");
            goto fail;
        }
    }

    if (socket_options->option_reuse_addr && socketOptionReuseAddr(sockfd, 1) != 0)
    {
        LOGE("TcpConnector: set socket reuseaddr failed");
        goto fail;
    }

    if (! bindSourceIpIfNeeded(sockfd, addr_type, socket_options))
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
    ls->connect_start_ms = getTimeOfDayMS();
    if (wioConnect(io) != 0)
    {
        tcpconnectorRemoveIdleHandleOnConnectFailure(t, l, ls, io);
        weventSetUserData(io, NULL);
        wioClose(io);
        ls->io = NULL;
        goto fail;
    }

    return true;
fail:
    SAFE_CLOSESOCKET(sockfd);
    tcpconnectorRecordDestinationFailure(t, ls->destination_index);
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

    address_context_t *dest_ctx = &(l->routing_context.dest_ctx);

    const char *domain = dest_ctx->domain != NULL ? dest_ctx->domain : "<unknown>";

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        LOGE("TcpConnector: async dns resolve failed for %s: %s", domain,
             error != NULL ? error : ares_strerror(status));
        tcpconnectorRecordDestinationFailure(t, request->destination_index);
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        memoryFree(request);
        lineUnlock(l);
        return;
    }

    const dns_resolved_addr_t *selected =
        tcpconnectorSelectResolvedAddress(addrs, naddrs, request->socket_options.domain_strategy);
    if (! tcpconnectorApplyResolvedAddress(dest_ctx, selected))
    {
        LOGE("TcpConnector: async dns resolve returned no usable address for %s", domain);
        tcpconnectorRecordDestinationFailure(t, request->destination_index);
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

    uint64_t                      outbound_ip_range = request->outbound_ip_range;
    tcpconnector_socket_options_t socket_options    = request->socket_options;
    memoryFree(request);

    discard tcpconnectorBeginConnect(t, l, ls, outbound_ip_range, &socket_options);
    lineUnlock(l);
}

static bool tcpconnectorStartDnsResolve(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls, uint64_t outbound_ip_range,
                                        const tcpconnector_socket_options_t *socket_options)
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
        .socket_options    = *socket_options,
        .destination_index = ls->destination_index,
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

static void tcpconnectorRaceAttemptFree(tcpconnector_race_attempt_t *attempt)
{
    if (attempt == NULL)
    {
        return;
    }

    addresscontextReset(&attempt->dest_ctx);
    memoryFree(attempt);
}

static void tcpconnectorRaceDetachAttempt(tcpconnector_lstate_t *ls, tcpconnector_race_attempt_t *attempt)
{
    if (attempt == NULL)
    {
        return;
    }

    if (ls->race_attempts != NULL && attempt->slot < ls->race_attempt_count &&
        ls->race_attempts[attempt->slot] == attempt)
    {
        ls->race_attempts[attempt->slot] = NULL;
    }

    if (! attempt->completed && ls->race_open_attempts > 0)
    {
        ls->race_open_attempts -= 1;
    }
    attempt->completed = true;
}

static void tcpconnectorRaceCancelAttempt(tcpconnector_lstate_t *ls, tcpconnector_race_attempt_t *attempt)
{
    if (attempt == NULL)
    {
        return;
    }

    attempt->cancelled = true;
    tcpconnectorRaceDetachAttempt(ls, attempt);

    if (attempt->io != NULL)
    {
        weventSetUserData(attempt->io, NULL);
        wioClose(attempt->io);
        attempt->io = NULL;
    }

    tcpconnectorRaceAttemptFree(attempt);
}

static void tcpconnectorRaceCancelLosers(tcpconnector_lstate_t *ls, tcpconnector_race_attempt_t *winner)
{
    if (ls->race_attempts == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < ls->race_attempt_count; ++i)
    {
        tcpconnector_race_attempt_t *attempt = ls->race_attempts[i];
        if (attempt == NULL || attempt == winner)
        {
            continue;
        }

        tcpconnectorRaceCancelAttempt(ls, attempt);
    }
}

static void tcpconnectorRaceFinishIfAllFailed(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls)
{
    if (ls->role != kTcpConnectorLineRoleRace || ls->race_completed || ls->race_open_attempts > 0)
    {
        return;
    }

    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

static void tcpconnectorRaceOnClose(wio_t *io)
{
    tcpconnector_race_attempt_t *attempt = weventGetUserdata(io);
    if (attempt == NULL)
    {
        return;
    }

    weventSetUserData(io, NULL);
    attempt->io = NULL;

    tunnel_t *t = attempt->tunnel;
    line_t   *l = attempt->line;

    if (! lineIsAlive(l))
    {
        tcpconnectorRaceAttemptFree(attempt);
        return;
    }

    tcpconnector_lstate_t *ls = lineGetState(l, t);
    if (ls->role != kTcpConnectorLineRoleRace || ls->race_completed)
    {
        tcpconnectorRaceAttemptFree(attempt);
        return;
    }

    tcpconnectorRecordDestinationFailure(t, attempt->destination_index);
    tcpconnectorRaceDetachAttempt(ls, attempt);
    tcpconnectorRaceAttemptFree(attempt);
    tcpconnectorRaceFinishIfAllFailed(t, l, ls);
}

static void tcpconnectorRaceOnConnected(wio_t *io)
{
    tcpconnector_race_attempt_t *attempt = weventGetUserdata(io);
    if (attempt == NULL)
    {
        return;
    }

    tunnel_t *t = attempt->tunnel;
    line_t   *l = attempt->line;

    if (! lineIsAlive(l))
    {
        weventSetUserData(io, NULL);
        wioClose(io);
        attempt->io = NULL;
        tcpconnectorRaceAttemptFree(attempt);
        return;
    }

    tcpconnector_tstate_t *ts = tunnelGetState(t);
    tcpconnector_lstate_t *ls = lineGetState(l, t);
    if (ls->role != kTcpConnectorLineRoleRace || ls->race_completed)
    {
        weventSetUserData(io, NULL);
        wioClose(io);
        attempt->io = NULL;
        tcpconnectorRaceAttemptFree(attempt);
        return;
    }

    ls->race_completed    = true;
    ls->destination_index = attempt->destination_index;
    ls->connect_start_ms  = attempt->start_ms;
    ls->io                = io;

    ls->idle_handle = idletableCreateItem(ts->idle_table, tcpconnectorIdleKey(io), ls,
                                          tcpconnectorOnIdleConnectionExpire, lineGetWID(l), kReadWriteTimeoutMs);
    if (UNLIKELY(ls->idle_handle == NULL))
    {
        LOGE("TcpConnector: failed to register race winner idle item for FD:%x", wioGetFD(io));
        tcpconnectorRaceCancelLosers(ls, attempt);
        weventSetUserData(io, NULL);
        wioClose(io);
        ls->io = NULL;
        tcpconnectorRaceDetachAttempt(ls, attempt);
        tcpconnectorRaceAttemptFree(attempt);
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tcpconnectorRaceCancelLosers(ls, attempt);
    tcpconnectorRaceDetachAttempt(ls, attempt);

    attempt->io = NULL;
    tcpconnectorRaceAttemptFree(attempt);

    weventSetUserData(io, ls);
    wioSetCallBackConnect(io, tcpconnectorOnOutBoundConnected);
    wioSetCallBackClose(io, tcpconnectorOnClose);
    tcpconnectorOnOutBoundConnected(io);
}

static bool tcpconnectorStartRaceAttempt(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls,
                                         uint32_t destination_index, uint32_t slot,
                                         const address_context_t *original_dest_ctx, address_context_t *src_ctx)
{
    tcpconnector_tstate_t      *ts          = tunnelGetState(t);
    tcpconnector_destination_t *destination = &ts->destinations[destination_index];
    tcpconnector_race_attempt_t *attempt    = memoryAllocateZero(sizeof(*attempt));
    if (attempt == NULL)
    {
        return false;
    }

    attempt->tunnel            = t;
    attempt->line              = l;
    attempt->destination_index = destination_index;
    attempt->slot              = slot;
    attempt->outbound_ip_range = destination->outbound_ip_range;
    attempt->socket_options    = getDestinationSocketOptions(destination);
    attempt->start_ms          = getTimeOfDayMS();

    setupDestinationAddress(&destination->dest_addr_selected, &destination->constant_dest_addr, &attempt->dest_ctx,
                            original_dest_ctx, src_ctx);
    setupDestinationPort(&destination->dest_port_selected, &destination->constant_dest_addr, &attempt->dest_ctx,
                         original_dest_ctx, src_ctx);
    addresscontextSetDomainStrategy(&attempt->dest_ctx, (enum domain_strategy) attempt->socket_options.domain_strategy);

    if (! addresscontextHasPort(&attempt->dest_ctx) || ! attempt->dest_ctx.type_ip)
    {
        tcpconnectorRecordDestinationFailure(t, destination_index);
        tcpconnectorRaceAttemptFree(attempt);
        return false;
    }

    if (attempt->outbound_ip_range > 0 &&
        ! tcpconnectorApplyFreeBindRandomDestIp(&attempt->dest_ctx, attempt->outbound_ip_range))
    {
        tcpconnectorRecordDestinationFailure(t, destination_index);
        tcpconnectorRaceAttemptFree(attempt);
        return false;
    }

    int addr_type = attempt->dest_ctx.ip_address.type == IPADDR_TYPE_V4 ? AF_INET : AF_INET6;
    int sockfd    = (int) socket(addr_type, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        tcpconnectorRecordDestinationFailure(t, destination_index);
        tcpconnectorRaceAttemptFree(attempt);
        return false;
    }

    if (attempt->socket_options.option_tcp_no_delay)
    {
        tcpNoDelay(sockfd, 1);
    }
    if (! socketOptionApplySendBuffer(sockfd, attempt->socket_options.send_buffer_size) ||
        ! socketOptionApplyRecvBuffer(sockfd, attempt->socket_options.recv_buffer_size) ||
        socketOptionBindToDevice(sockfd, attempt->socket_options.interface_name) != 0 ||
        (attempt->socket_options.fwmark != kFwMarkInvalid &&
         socketOptionSetFwMark(sockfd, attempt->socket_options.fwmark) < 0) ||
        (attempt->socket_options.option_reuse_addr && socketOptionReuseAddr(sockfd, 1) != 0) ||
        ! bindSourceIpIfNeeded(sockfd, addr_type, &attempt->socket_options))
    {
        SAFE_CLOSESOCKET(sockfd);
        tcpconnectorRecordDestinationFailure(t, destination_index);
        tcpconnectorRaceAttemptFree(attempt);
        return false;
    }

    wio_t *io = wioGet(getWorkerLoop(getWID()), sockfd);
    assert(io != NULL);
    sockfd = -1;

    sockaddr_u addr = addresscontextToSockAddr(&attempt->dest_ctx);
    wioSetPeerAddr(io, (struct sockaddr *) &addr, (int) sockaddrLen(&addr));
    wioSetCallBackConnect(io, tcpconnectorRaceOnConnected);
    wioSetCallBackClose(io, tcpconnectorRaceOnClose);
    wioSetConnectTimeout(io, (int) ts->race_timeout_ms);
    weventSetUserData(io, attempt);

    attempt->io = io;
    ls->race_attempts[slot] = attempt;
    ls->race_open_attempts += 1;

    if (wioConnect(io) != 0)
    {
        tcpconnectorRaceDetachAttempt(ls, attempt);
        weventSetUserData(io, NULL);
        wioClose(io);
        attempt->io = NULL;
        tcpconnectorRecordDestinationFailure(t, destination_index);
        tcpconnectorRaceAttemptFree(attempt);
        return false;
    }

    return true;
}

static uint32_t tcpconnectorSelectRaceDestinationIndices(tcpconnector_tstate_t *ts, uint32_t *indices,
                                                         uint32_t max_indices)
{
    uint32_t limit = ts->race_tries;
    if (limit > max_indices)
    {
        limit = max_indices;
    }
    if (limit > ts->destinations_count)
    {
        limit = ts->destinations_count;
    }

    bool     require_healthy = countHealthyDestinations(ts) > 0;
    uint32_t selected        = 0;
    uint32_t start           = (uint32_t) atomic_fetch_add(&ts->destination_round_index, limit);

    for (uint32_t offset = 0; offset < ts->destinations_count && selected < limit; ++offset)
    {
        uint32_t index = (start + offset) % ts->destinations_count;
        if (! require_healthy || destinationIsHealthy(ts, index))
        {
            indices[selected++] = index;
        }
    }

    for (uint32_t offset = 0; offset < ts->destinations_count && selected < limit; ++offset)
    {
        uint32_t index = (start + offset) % ts->destinations_count;
        bool     used  = false;
        for (uint32_t i = 0; i < selected; ++i)
        {
            if (indices[i] == index)
            {
                used = true;
                break;
            }
        }
        if (! used)
        {
            indices[selected++] = index;
        }
    }

    return selected;
}

void tcpconnectorRaceTimeoutTask(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    tcpconnector_lstate_t *ls = lineGetState(l, t);
    if (ls->role != kTcpConnectorLineRoleRace || ls->race_completed)
    {
        return;
    }

    LOGW("TcpConnector: address race timed out waiting for a successful TCP connect");
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

static void tcpconnectorTunnelRaceUpStreamInit(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    uint32_t *indices = memoryAllocate(sizeof(uint32_t) * (size_t) ts->race_tries);

    if (indices == NULL)
    {
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    uint32_t candidate_count = tcpconnectorSelectRaceDestinationIndices(ts, indices, ts->race_tries);
    if (candidate_count == 0)
    {
        memoryFree(indices);
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    ls->role               = kTcpConnectorLineRoleRace;
    ls->write_paused       = true;
    ls->race_attempt_count = candidate_count;
    ls->race_attempts      = memoryAllocateZero(sizeof(*ls->race_attempts) * (size_t) candidate_count);
    if (ls->race_attempts == NULL)
    {
        memoryFree(indices);
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    address_context_t original_dest_ctx = {0};
    addresscontextAddrCopy(&original_dest_ctx, &l->routing_context.dest_ctx);
    address_context_t *src_ctx = &l->routing_context.src_ctx;

    for (uint32_t i = 0; i < candidate_count; ++i)
    {
        discard tcpconnectorStartRaceAttempt(t, l, ls, indices[i], i, &original_dest_ctx, src_ctx);
    }

    addresscontextReset(&original_dest_ctx);
    memoryFree(indices);

    if (ls->race_open_attempts == 0)
    {
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    lineScheduleDelayedTask(l, tcpconnectorRaceTimeoutTask, ts->race_timeout_ms, t);
}

void tcpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    tcpconnector_lstate_t *ls = lineGetState(l, t);

    tcpconnectorLinestateInitialize(ls);

    ls->tunnel       = t;
    ls->line         = l;
    ls->write_paused = true;

    if (ts->address_selection == kTcpConnectorAddressSelectionRace)
    {
        tcpconnectorTunnelRaceUpStreamInit(t, l, ls);
        return;
    }

    // findout how to deal with destination address
    address_context_t *dest_ctx = &(l->routing_context.dest_ctx);
    address_context_t *src_ctx  = &(l->routing_context.src_ctx);
    const dynamic_value_t    *dest_addr_selected = &ts->dest_addr_selected;
    const dynamic_value_t    *dest_port_selected = &ts->dest_port_selected;
    const address_context_t  *constant_dest_addr = &ts->constant_dest_addr;
    uint64_t                  outbound_ip_range  = ts->outbound_ip_range;
    tcpconnector_socket_options_t socket_options = getRootSocketOptions(ts);
    uint32_t selected_destination_index = selectDestinationIndex(ts);

    if (selected_destination_index != kTcpConnectorNoDestinationIndex)
    {
        const tcpconnector_destination_t *selected_destination = &ts->destinations[selected_destination_index];
        dest_addr_selected = &selected_destination->dest_addr_selected;
        dest_port_selected = &selected_destination->dest_port_selected;
        constant_dest_addr = &selected_destination->constant_dest_addr;
        outbound_ip_range  = selected_destination->outbound_ip_range;
        socket_options     = getDestinationSocketOptions(selected_destination);
        ls->destination_index = selected_destination_index;
    }

    address_context_t original_dest_ctx = {0};
    addresscontextAddrCopy(&original_dest_ctx, dest_ctx);

    setupDestinationAddress(dest_addr_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    setupDestinationPort(dest_port_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) socket_options.domain_strategy);
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
        if (! tcpconnectorStartDnsResolve(t, l, ls, outbound_ip_range, &socket_options))
        {
            goto fail;
        }
        return;
    }

    if (! tcpconnectorBeginConnect(t, l, ls, outbound_ip_range, &socket_options))
    {
        return;
    }

    return;
fail:
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
