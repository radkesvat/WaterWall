#include "structure.h"

#include "loggers/network_logger.h"

static void ptcEmitPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3);

static void ptcEmitPacketCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg1;
    discard arg3;
    sbufDestroy(arg2);
}

static void ptcEmitPacketBufferAdmitted(tunnel_t *t, line_t *packet_line, sbuf_t *buf)
{
#ifdef DEBUG
    lineRef(packet_line);
#endif

    tunnelPrevDownStreamPayload(t, packet_line, buf);

#ifdef DEBUG
    if (! lineIsAlive(packet_line))
    {
        LOGF("PacketsToConnection: packet line died during runtime, packet tunnel contract was violated");
        abortProgramNow(1);
    }

    lineUnref(packet_line);
#endif
}

bool ptcEmitPacketBuffer(tunnel_t *t, line_t *packet_line, sbuf_t *buf)
{
    ptc_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(ptcTunnelIsStopping(t) || ! quiescenceGateEnter(&state->output_gate)))
    {
        lineReuseBuffer(packet_line, buf);
        return false;
    }

    if (UNLIKELY(ptcTunnelIsStopping(t)))
    {
        quiescenceGateLeave(&state->output_gate);
        lineReuseBuffer(packet_line, buf);
        return false;
    }

    ptcEmitPacketBufferAdmitted(t, packet_line, buf);
    quiescenceGateLeave(&state->output_gate);
    return true;
}

static void ptcEmitPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg3;

    tunnel_t     *t     = arg1;
    sbuf_t       *buf   = arg2;
    ptc_tstate_t *state = tunnelGetState(t);

    /* Worker messages settle before tunnel destruction. No cancellation path
     * depends on this tunnel, its packet line, or an owner-local pool. */
    if (UNLIKELY(ptcTunnelIsStopping(t) || ! quiescenceGateEnter(&state->output_gate)))
    {
        bufferpoolReuseBuffer(worker->buffer_pool, buf);
        return;
    }

    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), worker->wid);
    if (UNLIKELY(packet_line == NULL || ptcTunnelIsStopping(t)))
    {
        quiescenceGateLeave(&state->output_gate);
        bufferpoolReuseBuffer(worker->buffer_pool, buf);
        return;
    }

    ptcEmitPacketBufferAdmitted(t, packet_line, buf);
    quiescenceGateLeave(&state->output_gate);
}

static err_t interfaceInit(struct netif *netif)
{
    netif->flags |= NETIF_FLAG_PRETEND;
    netif->output = ptcNetifOutput;

    const interface_route_context_t *route = netif->state;
    const ptc_tstate_t              *state = tunnelGetState(route->tunnel);
    netif->mtu                             = state->mtu;
    if (packettunnelTrustedChecksumsActive(route->tunnel))
    {
        netif->chksum_flags &=
            (uint16_t) ~(NETIF_CHECKSUM_CHECK_IP | NETIF_CHECKSUM_CHECK_TCP | NETIF_CHECKSUM_CHECK_UDP);
        netif->ww_partial_transport_checksum = 1;
    }

    return ERR_OK;
}

static void ptcDestroyUdpFlowPcbs(interface_route_context_t *route)
{
    c_foreach(i, ptc_udp_flow_map_t, route->udp_flows)
    {
        line_t *line = i.ref->second;
        if (line != NULL && lineIsAlive(line))
        {
            ptc_lstate_t *ls = lineGetState(line, route->tunnel);
            if (ls->kind == kPtcLineKindUdp && ls->udp_pcb != NULL)
            {
                udp_recv(ls->udp_pcb, NULL, NULL);
                udp_remove(ls->udp_pcb);
                ls->udp_pcb   = NULL;
                ls->route_ctx = NULL;
            }
        }
    }
}

static void ptcDestroyRouteContext(interface_route_context_t *route)
{
    ptcDestroyUdpFlowPcbs(route);
    ptc_udp_flow_map_t_drop(&route->udp_flows);
    if (route->tcp_pcb != NULL)
    {
        tcp_arg(route->tcp_pcb, NULL);
        tcp_accept(route->tcp_pcb, NULL);
        if (tcp_close(route->tcp_pcb) != ERR_OK)
        {
            tcp_abort(route->tcp_pcb);
        }
    }
    if (route->udp_pcb != NULL)
    {
        udp_recv(route->udp_pcb, NULL, NULL);
        udp_remove(route->udp_pcb);
    }
    discard ip4_reass_purge_netif(&route->netif);
    netif_remove(&route->netif);
    memoryFree(route);
}

void ptcDestroyWorkerRoute(tunnel_t *t, wid_t wid)
{
    ptc_tstate_t *state = tunnelGetState(t);
    assert(currentThreadIsEventWorkerWID(wid));
    if (state->routes_v4 == NULL)
        return;
    assert(wid < state->route_worker_count);
    interface_route_context_t *route = state->routes_v4[wid];
    state->routes_v4[wid]            = NULL;
    if (route != NULL)
    {
        ww_lwip_engine_t *engine = route->engine;
        ww_lwip_engine_t *previous;
        const bool        entered = wwLwipEngineEnter(engine, &previous);
        assert(entered);
        discard entered;
        ptcTcpDrainDestroyRoute(route);
        ptcDestroyRouteContext(route);
        wwLwipEngineLeave(engine, previous);
    }
}

static interface_route_context_t **ptcRouteSlot(ptc_tstate_t *state, wid_t packet_wid)
{
    return &state->routes_v4[(uint32_t) packet_wid];
}

interface_route_context_t *ptcFindOrCreateRouteContextV4(tunnel_t *t, wid_t packet_wid, const ip4_addr_t *dest_ip)
{
    discard dest_ip;
    assert(currentThreadIsEventWorkerWID(packet_wid));
    wwLwipEngineAssertCurrent();

    ptc_tstate_t *state = tunnelGetState(t);
    if (UNLIKELY(! workerWIDIsRegistered(packet_wid) || state->routes_v4 == NULL ||
                 (uint32_t) packet_wid >= state->route_worker_count))
    {
        return NULL;
    }

    interface_route_context_t **slot = ptcRouteSlot(state, packet_wid);
    interface_route_context_t  *cur  = *slot;
    if (cur != NULL)
    {
        assert(cur->engine == wwLwipEngineCurrent());
        return cur;
    }

    cur = memoryAllocateZero(sizeof(*cur));
    if (UNLIKELY(cur == NULL))
    {
        return NULL;
    }

    cur->engine     = wwLwipEngineCurrent();
    cur->tunnel     = t;
    cur->packet_wid = packet_wid;
    cur->udp_flows  = ptc_udp_flow_map_t_init();

    if (! ptc_udp_flow_map_t_reserve(&cur->udp_flows, 64) || ptc_udp_flow_map_t_capacity(&cur->udp_flows) < 64)
    {
        ptc_udp_flow_map_t_drop(&cur->udp_flows);
        memoryFree(cur);
        return NULL;
    }

    if (netif_add_noaddr(&cur->netif, cur, interfaceInit, ip_input) == NULL)
    {
        ptc_udp_flow_map_t_drop(&cur->udp_flows);
        memoryFree(cur);
        return NULL;
    }

    ip4_addr_t addr;
    ip4_addr_t mask;
    ip4_addr_t gw;

    ip4_addr_set_loopback(&addr);
    ip4_addr_set_any(&mask);
    ip4_addr_set_any(&gw);
    netif_set_addr(&cur->netif, &addr, &mask, &gw);

    netif_set_up(&cur->netif);
    netif_set_link_up(&cur->netif);

    if (ptcEnsureTcpListener(cur, t, NULL, 0) != ERR_OK || ptcEnsureUdpListener(cur, t, NULL, 0) != ERR_OK)
    {
        ptcDestroyRouteContext(cur);
        return NULL;
    }

    *slot = cur;

    return cur;
}

err_t ptcEnsureTcpListener(interface_route_context_t *route_ctx, tunnel_t *t, const ip_addr_t *dest_ip,
                           uint16_t dest_port)
{
    discard t;
    discard dest_ip;
    discard dest_port;

    if (route_ctx->tcp_pcb != NULL)
    {
        return ERR_OK;
    }

    struct tcp_pcb *original_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    err_t           err          = ERR_OK;

    if (original_pcb == NULL)
    {
        return ERR_MEM;
    }

    err = tcp_bind_netif(original_pcb, &route_ctx->netif);
    if (err != ERR_OK)
    {
        if (tcp_close(original_pcb) != ERR_OK)
        {
            tcp_abort(original_pcb);
        }
        return err;
    }

    err = tcp_bind(original_pcb, NULL, 0);
    if (err != ERR_OK)
    {
        if (tcp_close(original_pcb) != ERR_OK)
        {
            tcp_abort(original_pcb);
        }
        return err;
    }

    struct tcp_pcb *listener_pcb = tcp_listen_with_backlog_and_err(original_pcb, TCP_DEFAULT_LISTEN_BACKLOG, &err);
    if (listener_pcb == NULL || err != ERR_OK)
    {
        struct tcp_pcb *failed_pcb = listener_pcb != NULL ? listener_pcb : original_pcb;
        if (tcp_close(failed_pcb) != ERR_OK)
        {
            tcp_abort(failed_pcb);
        }
        return err != ERR_OK ? err : ERR_MEM;
    }

    route_ctx->tcp_pcb = listener_pcb;
    tcp_arg(listener_pcb, route_ctx);
    tcp_accept(listener_pcb, lwipThreadPtcTcpAccptCallback);

    return ERR_OK;
}

err_t ptcEnsureUdpListener(interface_route_context_t *route_ctx, tunnel_t *t, const ip_addr_t *dest_ip,
                           uint16_t dest_port)
{
    discard t;
    discard dest_ip;
    discard dest_port;

    if (route_ctx->udp_pcb != NULL)
    {
        return ERR_OK;
    }

    struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    err_t           err;

    if (pcb == NULL)
    {
        return ERR_MEM;
    }

    err = udp_bind_netif(pcb, &route_ctx->netif);
    if (err != ERR_OK)
    {
        udp_remove(pcb);
        return err;
    }
    err = udp_bind(pcb, NULL, 0);
    if (err != ERR_OK)
    {
        udp_remove(pcb);
        return err;
    }

    route_ctx->udp_pcb = pcb;
    udp_recv(pcb, ptcUdpAccept, route_ctx);

    return ERR_OK;
}

err_t ptcNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    discard ipaddr;

    interface_route_context_t *route_ctx  = netif->state;
    tunnel_t                  *t          = route_ctx->tunnel;
    wid_t                      packet_wid = route_ctx->packet_wid;
    ptc_tstate_t              *state      = tunnelGetState(t);

    assert(currentThreadIsEventWorkerWID(packet_wid));
    assert(route_ctx->engine == wwLwipEngineCurrent());
    /* Owner cleanup can emit while removing protocol objects; the closed node
     * gate prevents publication to a neighbor that has already stopped. */
    if (UNLIKELY(ptcTunnelIsStopping(t) || ! quiescenceGateEnter(&state->output_gate)))
    {
        return ERR_IF;
    }

    if (UNLIKELY(ptcTunnelIsStopping(t)))
    {
        quiescenceGateLeave(&state->output_gate);
        return ERR_IF;
    }

    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), packet_wid);
    assert(packet_line != NULL && lineIsOnCurrentEventWorker(packet_line));
    buffer_pool_t *pool   = lineGetBufferPool(packet_line);
    sbuf_t        *buf    = bufferpoolGetBestFit(pool, p->tot_len, bufferpoolGetLargeBufferPadding(pool));
    const uint32_t length = p->tot_len;
    uint32_t       copied = 0;
    /* Stop at this packet, even if next points into a pbuf packet queue. Empty
     * spans are legal. No lwIP storage escapes to the device writer. */
    for (const struct pbuf *span = p; span != NULL && copied < length; span = span->next)
    {
        const uint32_t count = min((uint32_t) span->len, length - copied);
        if (count != 0)
        {
            uint8_t *destination = (uint8_t *) sbufGetMutablePtr(buf) + copied;
            if (count < 64)
                memoryCopy(destination, span->payload, count);
            else
                memoryCopyLarge(destination, span->payload, count);
            copied += count;
        }
        if (span->tot_len == span->len)
            break;
    }
    if (UNLIKELY(copied != length))
    {
        lineReuseBuffer(packet_line, buf);
        quiescenceGateLeave(&state->output_gate);
        return ERR_BUF;
    }
    sbufSetLength(buf, length);

    if (packettunnelCanEnqueueDownstreamInline(t, packet_line))
    {
        ptcEmitPacketBufferAdmitted(t, packet_line, buf);
        quiescenceGateLeave(&state->output_gate);
        return ERR_OK;
    }

    /* Arbitrary neighbours can reenter TCP input scratch. Queue the same sbuf;
     * synchronous refusal and foreign cancellation destroy it exactly once. */
    const worker_message_submit_result_e queued = sendWorkerMessageForceQueueWithCleanup(
        packet_wid, (WorkerMessageCallback) ptcEmitPacketOnWorker, ptcEmitPacketCleanup, t, buf, NULL);
    quiescenceGateLeave(&state->output_gate);
    return queued == kWorkerMessageSubmitAccepted ? ERR_OK : ERR_MEM;
}
