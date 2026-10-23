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
    if (UNLIKELY(! currentThreadOwnsWorker(owner_wid)))
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
        assert(lineIsAlive(line));
    }

    if (line == NULL)
    {
        line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), owner_wid);

        ptc_lstate_t *ls = lineGetState(line, t);
        ip_addr_t     local_ip;

        ptcLinestateInitialize(ls, t, line, kPtcLineKindUdp, upcb);

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

        /* The owner found no matching flow and has not called any neighbour. */
        const bool inserted = ptc_udp_flow_map_t_insert(&route_ctx->udp_flows, key, line).inserted;
        assert(inserted);
        discard inserted;

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
    pbufLargeCopyToPtr(p, sbufGetMutablePtr(buf));
    pbuf_free(p);

    /* Init and Payload are queued, so no neighbour can close this line here.
     * UDP is intentionally lossy when the worker queue refuses admission. */
    const line_task_submit_result_e result = lineScheduleTaskWithBuf(line, ptcDeliverPayloadTask, t, buf, NULL);
    discard                         result;
}
