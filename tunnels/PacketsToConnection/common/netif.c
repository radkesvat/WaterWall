#include "structure.h"

#include "loggers/network_logger.h"

typedef struct ptc_packet_emit_msg_s
{
    uint32_t len;
    uint8_t  data[];
} ptc_packet_emit_msg_t;

static void ptcEmitPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3);

static void ptcEmitPacketCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg1;
    discard arg3;
    memoryFree(arg2);
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

    tunnel_t              *t          = arg1;
    ptc_packet_emit_msg_t *packet_msg = arg2;
    ptc_tstate_t          *state      = tunnelGetState(t);

    /*
     * Under lifecycle-v2, worker messages are settled before tunnel destruction.
     * Local stopping/output_gate checks ensure work does not cross into a neighbour
     * after admission has closed.
     */
    if (UNLIKELY(ptcTunnelIsStopping(t) || ! quiescenceGateEnter(&state->output_gate)))
    {
        memoryFree(packet_msg);
        return;
    }

    // The message was delivered to exactly one worker; take the packet line from
    // that worker instead of re-reading TLS.
    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), worker->wid);
    if (UNLIKELY(packet_line == NULL || ptcTunnelIsStopping(t)))
    {
        quiescenceGateLeave(&state->output_gate);
        memoryFree(packet_msg);
        return;
    }

    buffer_pool_t *pool = lineGetBufferPool(packet_line);
    sbuf_t        *buf  = bufferpoolGetBestFit(pool, packet_msg->len, bufferpoolGetLargeBufferPadding(pool));

    if (UNLIKELY(buf == NULL))
    {
        quiescenceGateLeave(&state->output_gate);
        memoryFree(packet_msg);
        return;
    }

    sbufSetLength(buf, packet_msg->len);
    memoryCopy(sbufGetMutablePtr(buf), packet_msg->data, packet_msg->len);
    memoryFree(packet_msg);

    ptcEmitPacketBufferAdmitted(t, packet_line, buf);
    quiescenceGateLeave(&state->output_gate);
}

static err_t interfaceInit(struct netif *netif)
{
    netif->flags |= NETIF_FLAG_PRETEND;
    netif->output = ptcNetifOutput;

    /*
     * A netif with mtu 0 makes lwIP skip ip4_frag() entirely, so this interface
     * would answer a fragmented request with one oversized raw packet that the
     * far side has no way to carry. Inheriting the core MTU keeps the return
     * direction bound by the same limit the packet topology was configured for.
     *
     * The floor is defensive rather than expected: core settings already refuse
     * anything below the IPv4 minimum, but lwIP derives its fragment size from
     * `(mtu - IP_HLEN) / 8`, and a value that made that zero would leave
     * ip4_frag() looping without progress while holding the global core lock.
     * A netif is not the place to discover that.
     */
    if (UNLIKELY(GLOBAL_MTU_SIZE < kPtcMinNetifMtu))
    {
        LOGW("PacketsToConnection: core mtu %u is below the IPv4 minimum, using %u for the virtual netif",
             (unsigned int) GLOBAL_MTU_SIZE,
             (unsigned int) kPtcMinNetifMtu);
        netif->mtu = kPtcMinNetifMtu;
    }
    else
    {
        netif->mtu = GLOBAL_MTU_SIZE;
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

void ptcDestroyRouteContexts(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);
    if (state->routes_v4 == NULL)
    {
        return;
    }

    for (uint32_t wid = 0; wid < state->route_worker_count; ++wid)
    {
        interface_route_context_t *route = state->routes_v4[wid];
        state->routes_v4[wid]            = NULL;
        if (route != NULL)
        {
            ptcDestroyRouteContext(route);
        }
    }
    memoryFree(state->routes_v4);
    state->routes_v4          = NULL;
    state->route_worker_count = 0;
}

static interface_route_context_t **ptcRouteSlot(ptc_tstate_t *state, wid_t packet_wid)
{
    return &state->routes_v4[(uint32_t) packet_wid];
}

interface_route_context_t *ptcFindOrCreateRouteContextV4(tunnel_t *t, wid_t packet_wid, const ip4_addr_t *dest_ip)
{
    discard dest_ip;

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
        return cur;
    }

    cur = memoryAllocateZero(sizeof(*cur));
    if (UNLIKELY(cur == NULL))
    {
        return NULL;
    }

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

    /*
     * Reached with the core lock held, and Stop takes that same lock to remove
     * these routes and netifs. Refusing here is what keeps Stop's own teardown
     * from emitting: netif_remove() and the reassembly purge behind it can both
     * reach an output callback, and a packet published then would arrive at a
     * neighbour that has already stopped.
     */
    if (UNLIKELY(ptcTunnelIsStopping(t) || ! quiescenceGateEnter(&state->output_gate)))
    {
        return ERR_IF;
    }

    /*
     * This callback is reached with lwIP's non-recursive core lock held. Always
     * queue, including on the target worker, so no neighbouring tunnel callback
     * runs inside that lock. The worker callback takes its own admission token;
     * this token protects only message allocation and queue publication.
     */
    ptc_packet_emit_msg_t *packet_msg = memoryAllocate(sizeof(*packet_msg) + p->tot_len);

    if (UNLIKELY(packet_msg == NULL))
    {
        quiescenceGateLeave(&state->output_gate);
        return ERR_MEM;
    }

    packet_msg->len = p->tot_len;
    pbufLargeCopyToPtr(p, packet_msg->data);

    // A refusal releases the message through ptcEmitPacketCleanup(), which frees
    // one global-allocator block and touches no worker-local pool - the only
    // release that is legal from this thread.
    const worker_message_submit_result_e queued = sendWorkerMessageForceQueueWithCleanup(
        packet_wid, (WorkerMessageCallback) ptcEmitPacketOnWorker, ptcEmitPacketCleanup, t, packet_msg, NULL);
    quiescenceGateLeave(&state->output_gate);
    if (queued != kWorkerMessageSubmitAccepted)
    {
        return ERR_MEM;
    }

    return ERR_OK;
}
