#include "structure.h"

#include "loggers/network_logger.h"

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
        if (! lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel))
        {
            discard ptcRequiredControlRefusedLocked(ls, "TCP error close");
        }
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

    if (err != ERR_OK)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }

        ptcDetachTcpPcbLocked(ls);
        if (tpcb != NULL)
        {
            tcp_abort(tpcb);
        }

        if (lineIsAlive(ls->line))
        {
            if (! lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel))
            {
                discard ptcRequiredControlRefusedLocked(ls, "TCP receive-error close");
            }
        }
        return ERR_ABRT;
    }

    if (p == NULL)
    {
        if (lineIsAlive(ls->line) && ! lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel))
        {
            if (ptcRequiredControlRefusedLocked(ls, "TCP peer-FIN close"))
            {
                return ERR_ABRT;
            }
        }
        return ERR_OK;
    }

    wid_t owner_wid = lineGetWID(ls->line);
    if (UNLIKELY(! currentThreadIsEventWorkerWID(owner_wid)))
    {
        if (! ls->refused_retry_queued)
        {
            ls->refused_retry_queued = true;
            if (! lineIsAlive(ls->line) || ! lineScheduleTask(ls->line, ptcRefusedDataRetryTask, ls->tunnel))
            {
                ls->refused_retry_queued = false;
                if (ptcRequiredControlRefusedLocked(ls, "refused TCP data replay"))
                {
                    return ERR_ABRT;
                }
            }
        }
        return ERR_MEM;
    }

    buffer_pool_t *pool = lineGetBufferPool(ls->line);
    sbuf_t        *buf  = bufferpoolGetBestFit(pool, p->tot_len, bufferpoolGetLargeBufferPadding(pool));

    sbufSetLength(buf, p->tot_len);
    pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->tot_len, 0);

    if (! lineIsAlive(ls->line))
    {
        /* This callback is on owner_wid and captured its pool before the
         * logical-death check. */
        bufferpoolReuseBuffer(pool, buf);
        return ERR_MEM;
    }

    if (! ptcReceiveCreditAccumulateLocked(ls, p->tot_len))
    {
        lineReuseBuffer(ls->line, buf);
        pbuf_free(p);
        return ERR_ABRT;
    }

    if (! lineScheduleTaskWithBuf(ls->line, ptcDeliverPayloadTask, ls->tunnel, buf))
    {
        /* Scheduler cleanup owns the copied sbuf; lwIP retains and replays p. */
        ptcReceiveCreditRollbackLocked(ls, p->tot_len);
        return ERR_MEM;
    }

    pbuf_free(p);
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
    if (UNLIKELY(! currentThreadIsEventWorkerWID(owner_wid)))
    {
        LOGW(
            "PacketsToConnection: tcp accept callback arrived on worker %d for route owned by worker %d; dropping flow",
            workerWIDForLog(getWID()),
            workerWIDForLog(owner_wid));
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    tunnel_t     *t  = route_ctx->tunnel;
    line_t       *l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), owner_wid);
    ptc_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(! ptcLinestateInitialize(ls, t, l, kPtcLineKindTcp, newpcb)))
    {
        /*
         * One flow's bookkeeping could not be allocated. The line never became
         * usable, so it is destroyed here and the peer sees a reset - every other
         * flow on this node keeps running.
         */
        LOGW("PacketsToConnection: out of memory accepting a tcp flow; resetting it");
        lineDestroy(l);
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    addresscontextSetIpPortProtocol(
        lineGetSourceAddressContext(l), &newpcb->remote_ip, newpcb->remote_port, IP_PROTO_TCP);
    if (! ptcFakeDnsApplyMappedDestination(
            t, lineGetDestinationAddressContext(l), &newpcb->local_ip, newpcb->local_port, IP_PROTO_TCP))
    {
        addresscontextSetIpPortProtocol(
            lineGetDestinationAddressContext(l), &newpcb->local_ip, newpcb->local_port, IP_PROTO_TCP);
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

        LOGD("PacketsToConnection: new tcp flow accepted [%s:%u] <= [%s:%u]",
             local_ip,
             (unsigned int) newpcb->local_port,
             remote_ip,
             (unsigned int) newpcb->remote_port);
    }

    if (! lineScheduleTask(l, ptcOpenLineTask, t))
    {
        discard ptcRequiredControlRefusedLocked(ls, "TCP accepted-line Init");
        return ERR_ABRT;
    }
    return ERR_OK;
}
