#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpconnector_tstate_t *state  = tunnelGetState(t);
    tcpconnector_lstate_t *lstate = lineGetState(l, t);

    tcpconnectorLinestateInitialize(lstate, lineGetWID(l));

    lstate->tunnel       = t;
    lstate->line         = l;
    lstate->write_paused = true;

    // findout how to deal with destination address
    address_context_t *dest_ctx = &(l->routing_context.dest_ctx);
    address_context_t *src_ctx  = &(l->routing_context.src_ctx);

    switch ((tcpconnector_strategy_e) state->dest_addr_selected.status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextAddrCopy(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextAddrCopy(dest_ctx, &(state->constant_dest_addr));
        break;
    default:
    case kTcpConnectorStrategyFromDest:
        break;
    }

    // findout how to deal with destination port
    switch ((tcpconnector_strategy_e) state->dest_port_selected.status)
    {
    case kTcpConnectorStrategyFromSource:
        addresscontextPortCopy(dest_ctx, src_ctx);
        break;
    case kTcpConnectorStrategyConstant:
        addresscontextPortCopy(dest_ctx, &(state->constant_dest_addr));
        break;
    default:
    case kTcpConnectorStrategyFromDest:
        break;
    }

    // resolve domain name if needed (TODO : make it async and consider domain strategy)
    if (! dest_ctx->type_ip)
    {
        if(dest_ctx->domain == NULL)
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
    if (state->outbound_ip_range > 0)
    {
        if (! tcpconnectorApplyFreeBindRandomDestIp(t, dest_ctx))
        {
            goto fail;
        }
    }

    // sockaddr_set_ipport(&(dest_ctx.addr), "127.0.0.1", 443);

    wloop_t *loop   = getWorkerLoop(getWID());
    int sockfd = socket(dest_ctx->ip_address.type, SOCK_STREAM, 0);

    if (sockfd == INVALID_SOCKET)
    {
        LOGE("TcpConnector: could not create socket");
        goto fail;
    }

    if (state->option_tcp_no_delay)
    {
        tcpNoDelay(sockfd, 1);
    }

    if (state->option_tcp_fast_open)
    {
        const int yes = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, (const char *) &yes, sizeof(yes));
    }

#ifdef OS_LINUX
    if (state->fwmark != kFwMarkInvalid)
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_MARK, &state->fwmark, sizeof(state->fwmark)) < 0)
        {
            LOGE("TcpConnector: setsockopt SO_MARK error");
            goto fail;
        }
    }
#endif

    wio_t *upstream_io = wioGet(loop, sockfd);
    assert(upstream_io != NULL);

    sockaddr_u addr = addresscontextToSockAddr(dest_ctx);

    wioSetPeerAddr(upstream_io, (struct sockaddr*)&(addr), (int) sockaddrLen(&(addr)));
    lstate->io = upstream_io;
    weventSetUserData(upstream_io, lstate);
    wioSetCallBackConnect(upstream_io, tcpconnectorOnOutBoundConnected);
    wioSetCallBackClose(upstream_io, tcpconnectorOnClose);

    // issue connect on the socket
    wioConnect(upstream_io);

    return;
fail:
    tcpconnectorLinestateDestroy(lstate);
    tunnelPrevdownStreamFinish(t, l);
}
