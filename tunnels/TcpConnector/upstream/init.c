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
                                    address_context_t *dest_ctx, address_context_t *src_ctx)
{
    switch ((tcpconnector_strategy_e) dest_addr_selected->status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextAddrCopy(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextAddrCopy(dest_ctx, constant_dest_addr);
        break;
    default:
    case kTcpConnectorStrategyFromDest:
        addresscontextSetProtocol(dest_ctx, IPPROTO_TCP);
        break;
    }
}

static void setupDestinationPort(const dynamic_value_t *dest_port_selected, const address_context_t *constant_dest_addr,
                                 address_context_t *dest_ctx, address_context_t *src_ctx)
{
    switch ((tcpconnector_strategy_e) dest_port_selected->status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextCopyPort(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextCopyPort(dest_ctx, (address_context_t *) constant_dest_addr);
        break;
    default:
    case kTcpConnectorStrategyFromDest:
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

    setupDestinationAddress(dest_addr_selected, constant_dest_addr, dest_ctx, src_ctx);
    setupDestinationPort(dest_port_selected, constant_dest_addr, dest_ctx, src_ctx);

    // resolve domain name if needed (TODO : make it async and consider domain strategy)
    if (! dest_ctx->type_ip)
    {
        if (dest_ctx->domain == NULL)
        {
            LOGF("TcpConnector: destination address is not set");
            goto fail;
        }

        if (! resolveContextSync(dest_ctx))
        {

            goto fail;
        }
    }

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

    int sockfd = (int) socket(addr_type, SOCK_STREAM, 0);

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
        tcpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    wioSetCallBackConnect(io, tcpconnectorOnOutBoundConnected);
    wioSetCallBackClose(io, tcpconnectorOnClose);
    // wioSetReadTimeout(lstate->io, kReadWriteTimeoutMs);

    // issue connect on the socket
    wioConnect(io);

    return;
fail:
    SAFE_CLOSESOCKET(sockfd);
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
