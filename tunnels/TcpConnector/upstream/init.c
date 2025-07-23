#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpconnector_tstate_t *ts  = tunnelGetState(t);
    tcpconnector_lstate_t *ls = lineGetState(l, t);

    tcpconnectorLinestateInitialize(ls);

    ls->tunnel       = t;
    ls->line         = l;
    ls->write_paused = true;

    // findout how to deal with destination address
    address_context_t *dest_ctx = &(l->routing_context.dest_ctx);
    address_context_t *src_ctx  = &(l->routing_context.src_ctx);

    switch ((tcpconnector_strategy_e) ts->dest_addr_selected.status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextAddrCopy(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextAddrCopy(dest_ctx, &(ts->constant_dest_addr));
        break;
    default:
    case kTcpConnectorStrategyFromDest:
        addresscontextSetProtocol(dest_ctx, IPPROTO_TCP);

        break;
    }

    // findout how to deal with destination port
    switch ((tcpconnector_strategy_e) ts->dest_port_selected.status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextCopyPort(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextCopyPort(dest_ctx, &(ts->constant_dest_addr));
        break;
    default:
    case kTcpConnectorStrategyFromDest:
        break;
    }

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
    if (ts->outbound_ip_range > 0)
    {
        if (! tcpconnectorApplyFreeBindRandomDestIp(t, dest_ctx))
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

#ifdef TCP_FASTOPEN
    if (ts->option_tcp_fast_open)
    {
        const int yes = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, (const char *) &yes, sizeof(yes));
    }
#endif

#if defined(SO_MARK)
    if (ts->fwmark != kFwMarkInvalid)
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_MARK, &ts->fwmark, sizeof(ts->fwmark)) < 0)
        {
            LOGE("TcpConnector: setsockopt SO_MARK error");
            goto fail;
        }
    }
#endif

    wio_t *io = wioGet(loop, sockfd);
    assert(io != NULL);

    sockaddr_u addr = addresscontextToSockAddr(dest_ctx);

    wioSetPeerAddr(io, (struct sockaddr *) &(addr), (int) sockaddrLen(&(addr)));
    ls->io = io;
    weventSetUserData(io, ls);
    wioSetCallBackConnect(io, tcpconnectorOnOutBoundConnected);
    wioSetCallBackClose(io, tcpconnectorOnClose);
    // wioSetReadTimeout(lstate->io, kReadWriteTimeoutMs);
    ls->idle_handle = idleItemNew(ts->idle_table, (hash_t) (wioGetFD(io)), ls, tcpconnectorOnIdleConnectionExpire, lineGetWID(l),
                                  kReadWriteTimeoutMs);

    // issue connect on the socket
    wioConnect(io);

    return;
fail:
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
