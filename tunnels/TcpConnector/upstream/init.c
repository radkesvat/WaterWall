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

static void setupDestinationAddress(const dynamic_value_t   *dest_addr_selected,
                                    const address_context_t *constant_dest_addr, address_context_t *dest_ctx,
                                    const address_context_t *original_dest_ctx, address_context_t *src_ctx)
{
    switch ((tcpconnector_strategy_e) dest_addr_selected->status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextCopy(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextCopy(dest_ctx, constant_dest_addr);
        break;
    case kTcpConnectorStrategyFromDest:
        addresscontextCopy(dest_ctx, original_dest_ctx);
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
    const char *source_ip                     = getSourceBindIp(socket_options, interface_ip, sizeof(interface_ip));

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

static bool tcpconnectorBeginConnect(tunnel_t *t, line_t *l, tcpconnector_lstate_t *ls, uint64_t outbound_ip_range,
                                     const tcpconnector_socket_options_t *socket_options)
{
    tcpconnector_tstate_t *ts       = tunnelGetState(t);
    address_context_t     *dest_ctx = &(l->routing_context.dest_ctx);
    int                    sockfd   = -1;

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

    if (egressPinApply(sockfd, addr_type, socket_options->interface_name) != 0)
    {
        LOGE("TcpConnector: egress pin failed");
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

    ls->idle_handle = localidletableCreateItem(tcpconnectorGetLineIdleTable(ts, l),
                                               tcpconnectorIdleKey(io),
                                               ls,
                                               tcpconnectorOnIdleConnectionExpire,
                                               kReadWriteTimeoutMs);
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

bool tcpconnectorDomainResolverPrepare(tunnel_t *resolver, tunnel_t *connector, line_t *l,
                                       domainresolver_direction_t direction, void *user_lstate)
{
    discard resolver;
    discard direction;

    tcpconnector_tstate_t                 *ts = tunnelGetState(connector);
    tcpconnector_domain_resolver_lstate_t *ls = user_lstate;

    // findout how to deal with destination address
    address_context_t                *dest_ctx             = &(l->routing_context.dest_ctx);
    address_context_t                *src_ctx              = &(l->routing_context.src_ctx);
    const dynamic_value_t            *dest_addr_selected   = &ts->dest_addr_selected;
    const dynamic_value_t            *dest_port_selected   = &ts->dest_port_selected;
    const address_context_t          *constant_dest_addr   = &ts->constant_dest_addr;
    uint64_t                          outbound_ip_range    = ts->outbound_ip_range;
    tcpconnector_socket_options_t     socket_options       = getRootSocketOptions(ts);
    const tcpconnector_destination_t *selected_destination = selectWeightedDestination(ts);

    if (selected_destination != NULL)
    {
        dest_addr_selected = &selected_destination->dest_addr_selected;
        dest_port_selected = &selected_destination->dest_port_selected;
        constant_dest_addr = &selected_destination->constant_dest_addr;
        outbound_ip_range  = selected_destination->outbound_ip_range;
        socket_options     = getDestinationSocketOptions(selected_destination);
    }

    address_context_t original_dest_ctx = {0};
    addresscontextCopy(&original_dest_ctx, dest_ctx);

    setupDestinationAddress(dest_addr_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    setupDestinationPort(dest_port_selected, constant_dest_addr, dest_ctx, &original_dest_ctx, src_ctx);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_TCP);
    addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) socket_options.domain_strategy);
    addresscontextReset(&original_dest_ctx);

    if (! addresscontextHasPort(dest_ctx))
    {
        LOGE("TcpConnector: destination port is not initialized");
        return false;
    }

    ls->outbound_ip_range = outbound_ip_range;
    ls->socket_options    = socket_options;

    return true;
}

void tcpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpconnector_tstate_t              *ts       = tunnelGetState(t);
    tcpconnector_lstate_t              *ls       = lineGetState(l, t);
    tcpconnector_domain_resolver_lstate_t *resolver_ls =
        domainresolverTunnelGetUserLineState(ts->domain_resolver_tunnel, l);
    address_context_t                  *dest_ctx = lineGetDestinationAddressContext(l);

    tcpconnectorLinestateInitialize(ls);
    if (UNLIKELY(resolver_ls == NULL))
    {
        LOGF("TcpConnector: internal DomainResolver prepare state is missing");
        terminateProgram(1);
    }

    ls->tunnel            = t;
    ls->line              = l;
    ls->write_paused      = true;
    ls->outbound_ip_range = resolver_ls->outbound_ip_range;
    ls->socket_options    = resolver_ls->socket_options;

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        LOGE("TcpConnector: destination address or port is not initialized");
        goto fail;
    }

    if (! tcpconnectorBeginConnect(t, l, ls, ls->outbound_ip_range, &ls->socket_options))
    {
        return;
    }

    return;

fail:
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
