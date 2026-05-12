#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *ptcAllocateTcpReadBuffer(line_t *line, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(line);

    if (len <= bufferpoolGetSmallBufferSize(pool))
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (len <= bufferpoolGetLargeBufferSize(pool))
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreateWithPadding(len, bufferpoolGetLargeBufferPadding(pool));
}

void lwipThreadPtcTcpConnectionErrorCallback(void *arg, err_t err)
{
    ptc_lstate_t *ls = arg;

    if (err != ERR_OK)
    {
        LOGD("PacketsToConnection: tcp connection error %d", err);
    }

    if (ls == NULL)
    {
        return;
    }

    ls->tcp_pcb = NULL;

    if (lineIsAlive(ls->line))
    {
        lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel);
    }
}

err_t lwipThreadPtcTcpRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    ptc_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kPtcLineKindTcp || ls->tcp_pcb != tpcb)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return ERR_OK;
    }

    if (err != ERR_OK || p == NULL)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }

        ptcDetachTcpPcbLocked(ls);
        if (tpcb != NULL)
        {
            if (tcp_close(tpcb) != ERR_OK)
            {
                tcp_abort(tpcb);
            }
        }

        if (lineIsAlive(ls->line))
        {
            lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel);
        }
        return ERR_OK;
    }

    wid_t owner_wid = lineGetWID(ls->line);
    if (UNLIKELY(getWID() != owner_wid))
    {
        LOGW("PacketsToConnection: tcp recv callback arrived on worker %u for line owned by worker %u; closing flow",
             (unsigned int) getWID(), (unsigned int) owner_wid);
        pbuf_free(p);
        ptcDetachTcpPcbLocked(ls);
        if (tcp_close(tpcb) != ERR_OK)
        {
            tcp_abort(tpcb);
        }

        if (lineIsAlive(ls->line))
        {
            lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel);
        }
        return ERR_OK;
    }

    sbuf_t *buf = ptcAllocateTcpReadBuffer(ls->line, p->tot_len);

    sbufSetLength(buf, p->tot_len);
    pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->tot_len, 0);
    pbuf_free(p);

    if (lineIsAlive(ls->line))
    {
        lineScheduleTaskWithBuf(ls->line, ptcDeliverPayloadTask, ls->tunnel, buf);
    }
    else
    {
        lineReuseBuffer(ls->line, buf);
    }

    return ERR_OK;
}

err_t lwipThreadPtcTcpAccptCallback(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    interface_route_context_t *route_ctx = arg;

    if (err != ERR_OK)
    {
        if (newpcb != NULL)
        {
            tcp_abort(newpcb);
        }
        return err;
    }

    if (route_ctx == NULL || newpcb == NULL)
    {
        if (newpcb != NULL)
        {
            tcp_abort(newpcb);
        }
        return ERR_ARG;
    }

    const wid_t owner_wid = route_ctx->packet_wid;
    if (UNLIKELY(getWID() != owner_wid))
    {
        LOGW("PacketsToConnection: tcp accept callback arrived on worker %u for route owned by worker %u; dropping flow",
             (unsigned int) getWID(), (unsigned int) owner_wid);
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    tunnel_t *t = route_ctx->tunnel;
    line_t   *l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), owner_wid);
    ptc_lstate_t *ls = lineGetState(l, t);

    ptcLinestateInitialize(ls, t, l, kPtcLineKindTcp, newpcb);

    addresscontextSetIpPortProtocol(lineGetSourceAddressContext(l), &newpcb->remote_ip, newpcb->remote_port,
                                    IP_PROTO_TCP);
    if (! ptcFakeDnsApplyMappedDestination(t, lineGetDestinationAddressContext(l), &newpcb->local_ip,
                                           newpcb->local_port, IP_PROTO_TCP))
    {
        addresscontextSetIpPortProtocol(lineGetDestinationAddressContext(l), &newpcb->local_ip, newpcb->local_port,
                                        IP_PROTO_TCP);
    }
    lineGetRoutingContext(l)->local_listener_port = newpcb->local_port;

    tcp_arg(newpcb, ls);
    tcp_sent(newpcb, ptcTcpSendCompleteCallback);
    tcp_recv(newpcb, lwipThreadPtcTcpRecvCallback);
    tcp_err(newpcb, lwipThreadPtcTcpConnectionErrorCallback);
    tcp_nagle_disable(newpcb);

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char local_ip[40];
        char remote_ip[40];

        stringCopyN(local_ip, ipAddrNetworkToAddress(&newpcb->local_ip), 40);
        stringCopyN(remote_ip, ipAddrNetworkToAddress(&newpcb->remote_ip), 40);

        LOGD("PacketsToConnection: new tcp flow accepted [%s:%u] <= [%s:%u]", local_ip,
             (unsigned int) newpcb->local_port, remote_ip, (unsigned int) newpcb->remote_port);
    }

    lineScheduleTask(l, ptcOpenLineTask, t);
    return ERR_OK;
}
