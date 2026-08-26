#include "structure.h"

#include "loggers/network_logger.h"

void ptcUdpAccept(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    discard p;
    discard addr;
    discard port;

    interface_route_context_t *route_ctx = arg;

    if (route_ctx == NULL || upcb == NULL)
    {
        return;
    }

    if (udp_bind_netif(upcb, &route_ctx->netif) != ERR_OK)
    {
        udp_remove(upcb);
        return;
    }
    udp_recv(upcb, ptcUdpReceived, route_ctx);
}

void ptcUdpReceived(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    interface_route_context_t *route_ctx = arg;

    if (route_ctx == NULL)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return;
    }

    if (p == NULL || upcb == NULL || addr == NULL || ! ipAddrIsV4(addr) || ! ipAddrIsV4(&upcb->local_ip))
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return;
    }

    const wid_t owner_wid = route_ctx->packet_wid;
    if (UNLIKELY(! currentThreadIsEventWorkerWID(owner_wid)))
    {
        LOGW("PacketsToConnection: udp recv callback arrived on worker %d for route owned by worker %d; dropping "
             "datagram",
             workerWIDForLog(getWID()),
             workerWIDForLog(owner_wid));
        pbuf_free(p);
        return;
    }

    ptc_udp_flow_key_t key = {
        .src_addr_network  = addr->u_addr.ip4.addr,
        .dest_addr_network = upcb->local_ip.u_addr.ip4.addr,
        .src_port          = port,
        .dest_port         = upcb->local_port,
    };

    tunnel_t               *t        = route_ctx->tunnel;
    line_t                 *line     = NULL;
    bool                    new_flow = false;
    ptc_udp_flow_map_t_iter flow_it  = ptc_udp_flow_map_t_find(&route_ctx->udp_flows, key);

    if (flow_it.ref != ptc_udp_flow_map_t_end(&route_ctx->udp_flows).ref)
    {
        line = flow_it.ref->second;
        if (! lineIsAlive(line))
        {
            ptc_udp_flow_map_t_erase_at(&route_ctx->udp_flows, flow_it);
            line = NULL;
        }
    }

    if (line == NULL)
    {
        line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), owner_wid);

        ptc_lstate_t *ls = lineGetState(line, t);
        ip_addr_t     local_ip;

        if (UNLIKELY(! ptcLinestateInitialize(ls, t, line, kPtcLineKindUdp, upcb)))
        {
            LOGW("PacketsToConnection: out of memory accepting a udp flow; dropping it");
            lineDestroy(line);
            pbuf_free(p);
            return;
        }

        ls->route_ctx      = route_ctx;
        ls->udp_flow_key   = key;
        ls->udp_local_addr = upcb->local_ip;
        ls->udp_peer_addr  = *addr;
        ls->udp_local_port = upcb->local_port;
        ls->udp_peer_port  = port;

        addresscontextSetIpPortProtocol(lineGetSourceAddressContext(line), addr, port, IP_PROTO_UDP);
        local_ip = upcb->local_ip;
        if (! ptcFakeDnsApplyMappedDestination(
                t, lineGetDestinationAddressContext(line), &local_ip, upcb->local_port, IP_PROTO_UDP))
        {
            addresscontextSetIpPortProtocol(
                lineGetDestinationAddressContext(line), &local_ip, upcb->local_port, IP_PROTO_UDP);
        }
        lineGetRoutingContext(line)->local_listener_port = upcb->local_port;

        if (! ptc_udp_flow_map_t_insert(&route_ctx->udp_flows, key, line).inserted)
        {
            LOGW("PacketsToConnection: duplicate UDP flow detected while creating a line, dropping datagram");
            // We are inside the lwIP udp recv callback and still hold LOCK_TCPIP_CORE.
            // Destroying the line inline is unsafe here because ptcLinestateDestroy()
            // re-enters LOCK_TCPIP_CORE (non-recursive mutex) and would deadlock, and the
            // line still owns its lwIP refs. Defer the full teardown to the owner worker;
            // ptcCloseLineFromNetwork() detaches the lwIP state and destroys the line state
            // outside the core lock. next_init was never sent, so no Finish is propagated.
            const line_task_submit_result_e result = lineScheduleTask(line, ptcCloseLineTask, t, NULL);
            if (result == kLineTaskSubmitRejectedSettled)
            {
                discard ptcRequiredControlRefusedLocked(ls, "duplicate UDP-flow close");
            }
            else
            {
                assert(result == kLineTaskSubmitAcceptedAsync);
            }
            pbuf_free(p);
            return;
        }

        new_flow = true;

        if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
        {
            char src_ip[40];
            char dst_ip[40];

            stringCopyN(src_ip, ipAddrNetworkToAddress(addr), 40);
            stringCopyN(dst_ip, ipAddrNetworkToAddress(&local_ip), 40);

            LOGD("PacketsToConnection: new udp flow accepted [%s:%u] <= [%s:%u]",
                 dst_ip,
                 (unsigned int) upcb->local_port,
                 src_ip,
                 (unsigned int) port);
        }
    }

    if (new_flow)
    {
        const line_task_submit_result_e result = lineScheduleTask(line, ptcOpenLineTask, t, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            /* Init is required control: publishing payload without it strands an owned line. */
            discard ptcRequiredControlRefusedLocked(lineGetState(line, t), "UDP-flow open");
            pbuf_free(p);
            return;
        }
        assert(result == kLineTaskSubmitAcceptedAsync);
    }

    buffer_pool_t *pool = lineGetBufferPool(line);
    sbuf_t        *buf  = bufferpoolGetBestFit(pool, p->tot_len, bufferpoolGetLargeBufferPadding(pool));
    sbufSetLength(buf, p->tot_len);
    pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->tot_len, 0);
    pbuf_free(p);

    if (lineIsAlive(line))
    {
        /* UDP is intentionally lossy when the worker queue refuses admission. */
        const line_task_submit_result_e result = lineScheduleTaskWithBuf(line, ptcDeliverPayloadTask, t, buf, NULL);
        discard                         result;
    }
    else
    {
        lineReuseBuffer(line, buf);
    }
}
