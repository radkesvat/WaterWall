#include "structure.h"

#include "loggers/network_logger.h"

static void ptcDeliverTcpReceiveTask(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *ls  = lineGetState(l, t);
    sbuf_t       *buf = ls->rx_delivery;
    assert(buf != NULL);
    /* Publish the empty slot before Init/Payload can reenter or finish this
     * line. Later input gets its own deferred delivery and FIFO position. */
    ls->rx_delivery = NULL;
    ptcDeliverPayloadTask(t, l, buf);
}

static sbuf_t *ptcAcquireReceiveBuffer(buffer_pool_t *pool, uint32_t length)
{
    const uint16_t    padding = bufferpoolGetLargeBufferPadding(pool);
    buffer_pool_fit_t fit;
    const bool        fits = bufferpoolQueryBestFit(pool, length, padding, &fit);
    assert(fits);
    discard fits;
    /* A custom oversized worker tier must not enlarge this bounded staging
     * buffer. Dedicated storage still keeps the onward chain's padding. */
    return fit.payload_capacity <= TCP_WND ? bufferpoolGetBestFit(pool, length, padding)
                                           : sbufCreateWithPadding(length, padding);
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
    ls->route_ctx = NULL;

    if (lineIsAlive(ls->line))
    {
        const line_task_submit_result_e result = lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            discard ptcRequiredControlRefusedLocked(ls, "TCP error close");
        }
        else
        {
            assert(result == kLineTaskSubmitAcceptedAsync);
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
            const line_task_submit_result_e result = lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel, NULL);
            if (result == kLineTaskSubmitRejectedSettled)
            {
                discard ptcRequiredControlRefusedLocked(ls, "TCP receive-error close");
            }
            else
            {
                assert(result == kLineTaskSubmitAcceptedAsync);
            }
        }
        return ERR_ABRT;
    }

    if (p == NULL)
    {
        if (lineIsAlive(ls->line))
        {
            const line_task_submit_result_e result = lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel, NULL);
            if (result == kLineTaskSubmitRejectedSettled)
            {
                if (ptcRequiredControlRefusedLocked(ls, "TCP peer-FIN close"))
                {
                    return ERR_ABRT;
                }
            }
            else
            {
                assert(result == kLineTaskSubmitAcceptedAsync);
            }
        }
        return ERR_OK;
    }

    wid_t owner_wid = lineGetWID(ls->line);
    if (UNLIKELY(! currentThreadIsEventWorkerWID(owner_wid)))
    {
        if (! ls->refused_retry_queued)
        {
            ls->refused_retry_queued         = true;
            line_task_submit_result_e result = kLineTaskSubmitRejectedSettled;
            if (lineIsAlive(ls->line))
            {
                result = lineScheduleTask(ls->line, ptcRefusedDataRetryTask, ls->tunnel, NULL);
            }
            if (result == kLineTaskSubmitRejectedSettled)
            {
                ls->refused_retry_queued = false;
                if (ptcRequiredControlRefusedLocked(ls, "refused TCP data replay"))
                {
                    return ERR_ABRT;
                }
            }
            else
            {
                assert(result == kLineTaskSubmitAcceptedAsync);
            }
        }
        return ERR_MEM;
    }

    if (! lineIsAlive(ls->line))
    {
        return ERR_MEM;
    }

    buffer_pool_t *pool    = lineGetBufferPool(ls->line);
    sbuf_t        *buf     = ls->rx_delivery;
    const uint32_t pending = buf != NULL ? sbufGetLength(buf) : 0;
    assert(pending <= TCP_WND);
    if (p->tot_len > TCP_WND - pending)
    {
        /* lwIP keeps this pbuf for replay; never consume a partial callback. */
        return ERR_MEM;
    }
    if (! ptcReceiveCreditAccumulateLocked(ls, p->tot_len))
    {
        pbuf_free(p);
        return ERR_ABRT;
    }

    const uint32_t length   = pending + p->tot_len;
    const bool     schedule = buf == NULL;
    if (schedule)
    {
        buf = ptcAcquireReceiveBuffer(pool, length);
    }
    else if (sbufGetMaximumWriteableSize(buf) < length)
    {
        const uint32_t capacity = sbufGetMaximumWriteableSize(buf);
        const uint32_t growth   = max(length, min((uint32_t) TCP_WND, capacity * 2U));
        sbuf_t        *grown    = ptcAcquireReceiveBuffer(pool, growth);
        memoryCopy(sbufGetMutablePtr(grown), sbufGetRawPtr(buf), pending);
        bufferpoolReuseBuffer(pool, buf);
        buf = grown;
    }
    pbuf_copy_partial(p, (uint8_t *) sbufGetMutablePtr(buf) + pending, p->tot_len, 0);
    sbufSetLength(buf, length);
    ls->rx_delivery = buf;

    if (schedule)
    {
        const line_task_submit_result_e result = lineScheduleTask(ls->line, ptcDeliverTcpReceiveTask, ls->tunnel, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            /* No task owns the staging buffer. Roll back this whole callback;
             * lwIP retains its pbuf, while owner Stop handles later cancellation. */
            ls->rx_delivery = NULL;
            bufferpoolReuseBuffer(pool, buf);
            ptcReceiveCreditRollbackLocked(ls, p->tot_len);
            return ERR_MEM;
        }
        assert(result == kLineTaskSubmitAcceptedAsync);
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

    ls->route_ctx = route_ctx;

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

    const line_task_submit_result_e result = lineScheduleTask(l, ptcOpenLineTask, t, NULL);
    if (result == kLineTaskSubmitRejectedSettled)
    {
        discard ptcRequiredControlRefusedLocked(ls, "TCP accepted-line Init");
        return ERR_ABRT;
    }
    assert(result == kLineTaskSubmitAcceptedAsync);
    return ERR_OK;
}
