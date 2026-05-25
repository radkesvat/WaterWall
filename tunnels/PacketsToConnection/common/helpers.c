#include "structure.h"

#include "loggers/network_logger.h"

typedef struct ptc_packet_emit_msg_s
{
    uint32_t len;
    uint8_t  data[];
} ptc_packet_emit_msg_t;

static void ptcWorkerMessageReceived(wevent_t *ev)
{
    worker_msg_t *msg = weventGetUserdata(ev);
    wid_t         wid = (wid_t) wloopGetWid(weventGetLoop(ev));

    msg->callback(getWorker(wid), msg->arg1, msg->arg2, msg->arg3);
    masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &msg, 1, NULL);
}

static bool ptcPostWorkerMessage(wid_t target_wid, WorkerMessageCallback callback, void *arg1, void *arg2, void *arg3)
{
    worker_msg_t *queue_msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(queue_msg), 1, NULL);
    *queue_msg = (worker_msg_t) {.callback = callback, .arg1 = arg1, .arg2 = arg2, .arg3 = arg3};

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_wid);
    ev.cb   = ptcWorkerMessageReceived;
    weventSetUserData(&ev, queue_msg);

    if (UNLIKELY(false == wloopPostEvent(getWorkerLoop(target_wid), &ev)))
    {
        masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &queue_msg, 1, NULL);
        return false;
    }

    return true;
}

static sbuf_t *ptcAllocateBufferForPool(buffer_pool_t *pool, uint32_t len)
{
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

static void ptcEmitPacketBuffer(tunnel_t *t, line_t *packet_line, sbuf_t *buf)
{
#ifdef DEBUG
    lineLock(packet_line);
#endif

    tunnelPrevDownStreamPayload(t, packet_line, buf);

#ifdef DEBUG
    if (! lineIsAlive(packet_line))
    {
        LOGF("PacketsToConnection: packet line died during runtime, packet tunnel contract was violated");
        terminateProgram(1);
    }

    lineUnlock(packet_line);
#endif
}

static void ptcEmitPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t              *t           = arg1;
    ptc_packet_emit_msg_t *packet_msg  = arg2;
    line_t                *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getWID());
    buffer_pool_t         *pool        = lineGetBufferPool(packet_line);
    sbuf_t                *buf         = ptcAllocateBufferForPool(pool, packet_msg->len);

    sbufSetLength(buf, packet_msg->len);
    memoryCopy(sbufGetMutablePtr(buf), packet_msg->data, packet_msg->len);
    memoryFree(packet_msg);

    ptcEmitPacketBuffer(t, packet_line, buf);
}

static err_t interfaceInit(struct netif *netif)
{
    netif->flags |= NETIF_FLAG_PRETEND;
    netif->output = ptcNetifOutput;
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

void ptcDestroyRouteContexts(interface_route_context_t *route_head)
{
    interface_route_context_t *route = route_head->next;
    route_head->next = NULL;

    while (route != NULL)
    {
        interface_route_context_t *next = route->next;

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
        netif_remove(&route->netif);
        memoryFree(route);

        route = next;
    }
}

interface_route_context_t *ptcFindOrCreateRouteContextV4(tunnel_t *t, wid_t packet_wid, const ip4_addr_t *dest_ip)
{
    discard dest_ip;

    ptc_tstate_t              *state = tunnelGetState(t);
    interface_route_context_t *prev  = &state->route_context4;
    interface_route_context_t *cur   = state->route_context4.next;

    while (cur != NULL)
    {
        if (cur->packet_wid == packet_wid)
        {
            break;
        }

        prev = cur;
        cur  = cur->next;
    }

    if (cur != NULL)
    {
        cur->last_tick = getTickMS();

        if (state->route_context4.next != cur)
        {
            prev->next                 = cur->next;
            cur->next                  = state->route_context4.next;
            state->route_context4.next = cur;
        }

        return cur;
    }

    cur = memoryAllocateZero(sizeof(interface_route_context_t));
    cur->tunnel     = t;
    cur->packet_wid = packet_wid;
    cur->udp_flows  = ptc_udp_flow_map_t_with_capacity(64);

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
    cur->last_tick            = getTickMS();
    cur->next                 = state->route_context4.next;
    state->route_context4.next = cur;

    return cur;
}

err_t ptcEnsureTcpListener(interface_route_context_t *route_ctx, tunnel_t *t, const ip_addr_t *dest_ip, uint16_t dest_port)
{
    discard t;
    discard dest_ip;
    discard dest_port;

    if (route_ctx->tcp_pcb != NULL)
    {
        return ERR_OK;
    }

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    err_t           err = ERR_OK;

    if (pcb == NULL)
    {
        return ERR_MEM;
    }

    tcp_bind_netif(pcb, &route_ctx->netif);

    err = tcp_bind(pcb, NULL, 0);
    if (err != ERR_OK)
    {
        tcp_close(pcb);
        return err;
    }

    pcb = tcp_listen_with_backlog_and_err(pcb, TCP_DEFAULT_LISTEN_BACKLOG, &err);
    if (pcb == NULL || err != ERR_OK)
    {
        return err != ERR_OK ? err : ERR_MEM;
    }

    route_ctx->tcp_pcb = pcb;
    tcp_arg(pcb, route_ctx);
    tcp_accept(pcb, lwipThreadPtcTcpAccptCallback);

    return ERR_OK;
}

err_t ptcEnsureUdpListener(interface_route_context_t *route_ctx, tunnel_t *t, const ip_addr_t *dest_ip, uint16_t dest_port)
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

    udp_bind_netif(pcb, &route_ctx->netif);
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

void updateCheckSumTcp(u16_t *_hc, const void *_orig, const void *_new, int n)
{
    const u16_t *orig = _orig;
    const u16_t *new  = _new;
    u16_t        hc   = ~*_hc;

    while (n--)
    {
        u32_t s = (u32_t) hc + ((~*orig) & 0xffffU) + *new;
        while (s & 0xffff0000U)
        {
            s = (s & 0xffffU) + (s >> 16);
        }

        hc = (u16_t) s;
        ++orig;
        ++new;
    }

    *_hc = ~hc;
}

void updateCheckSumUdp(u16_t *hc, const void *orig, const void *new, int n)
{
    if (! *hc)
    {
        return;
    }

    updateCheckSumTcp(hc, orig, new, n);
    if (! *hc)
    {
        *hc = 0xffffU;
    }
}

err_t ptcNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    discard ipaddr;

    interface_route_context_t *route_ctx   = netif->state;
    tunnel_t                  *t           = route_ctx->tunnel;
    wid_t                      current_wid = getWID();
    wid_t                      packet_wid  = route_ctx->packet_wid;

    if (current_wid == packet_wid)
    {
        line_t        *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), packet_wid);
        buffer_pool_t *pool        = lineGetBufferPool(packet_line);
        sbuf_t        *buf         = ptcAllocateBufferForPool(pool, p->tot_len);

        sbufSetLength(buf, p->tot_len);
        pbufLargeCopyToPtr(p, sbufGetMutablePtr(buf));

        ptcEmitPacketBuffer(t, packet_line, buf);
        return ERR_OK;
    }

    ptc_packet_emit_msg_t *packet_msg = memoryAllocate(sizeof(*packet_msg) + p->tot_len);
    packet_msg->len                   = p->tot_len;
    pbufLargeCopyToPtr(p, packet_msg->data);

    if (! ptcPostWorkerMessage(packet_wid, (WorkerMessageCallback) ptcEmitPacketOnWorker, t, packet_msg, NULL))
    {
        memoryFree(packet_msg);
        return ERR_MEM;
    }

    return ERR_OK;
}

void ptcDetachTcpPcbLocked(ptc_lstate_t *ls)
{
    struct tcp_pcb *pcb = ls->tcp_pcb;

    if (pcb == NULL)
    {
        return;
    }

    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_err(pcb, NULL);
    ls->tcp_pcb = NULL;
}

void ptcDetachUdpFlowLocked(ptc_lstate_t *ls)
{
    interface_route_context_t *route_ctx = ls->route_ctx;

    if (route_ctx == NULL)
    {
        ls->udp_pcb = NULL;
        return;
    }

    ptc_udp_flow_map_t_iter it = ptc_udp_flow_map_t_find(&route_ctx->udp_flows, ls->udp_flow_key);
    if (it.ref != ptc_udp_flow_map_t_end(&route_ctx->udp_flows).ref && it.ref->second == ls->line)
    {
        ptc_udp_flow_map_t_erase_at(&route_ctx->udp_flows, it);
    }

    if (ls->udp_pcb != NULL)
    {
        udp_recv(ls->udp_pcb, NULL, NULL);
        udp_remove(ls->udp_pcb);
    }

    ls->route_ctx = NULL;
    ls->udp_pcb   = NULL;
}

void ptcFlushWriteQueue(ptc_lstate_t *ls)
{
    struct tcp_pcb *tpcb      = ls->tcp_pcb;
    bool            wrote_any = false;

    if (tpcb == NULL)
    {
        return;
    }

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        sbuf_t  *buf       = bufferqueuePopFront(&ls->pause_queue);
        uint32_t buf_len   = sbufGetLength(buf);
        uint16_t available = tcp_sndbuf(tpcb);

        if (available == 0)
        {
            ls->write_paused = true;
            bufferqueuePushFront(&ls->pause_queue, buf);
            break;
        }

        uint16_t write_len = (uint16_t) min((uint32_t) available, buf_len);
        err_t    err       = tcp_write(tpcb, sbufGetMutablePtr(buf), write_len, TCP_WRITE_FLAG_COPY);

        if (err != ERR_OK)
        {
            ls->write_paused = true;
            bufferqueuePushFront(&ls->pause_queue, buf);
            break;
        }

        wrote_any = true;

        if (write_len == buf_len)
        {
            continue;
        }

        sbufShiftRight(buf, write_len);
        ls->write_paused = true;
        bufferqueuePushFront(&ls->pause_queue, buf);
        break;
    }

    if (wrote_any)
    {
        tcp_output(tpcb);
    }

    if (bufferqueueGetBufCount(&ls->pause_queue) == 0)
    {
        ls->write_paused = false;
    }
}

err_t ptcTcpSendCompleteCallback(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    ptc_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kPtcLineKindTcp || ls->tcp_pcb != tpcb)
    {
        return ERR_OK;
    }

    while (len > 0 && ! sbuf_ack_queue_t_is_empty(&ls->ack_queue))
    {
        sbuf_ack_t *ack       = sbuf_ack_queue_t_front_mut(&ls->ack_queue);
        uint16_t    remaining = (uint16_t) (ack->total - ack->written);
        uint16_t    cost      = min(remaining, len);

        ack->written += cost;
        len          -= cost;

        if (ack->written == ack->total)
        {
            if (ack->buf != NULL)
            {
                lineReuseBuffer(ls->line, ack->buf);
            }
            sbuf_ack_queue_t_pop_front(&ls->ack_queue);
        }
    }

    if (ls->write_paused)
    {
        ptcFlushWriteQueue(ls);
        if (! ls->write_paused && lineIsAlive(ls->line))
        {
            lineScheduleTask(ls->line, ptcResumeUpstreamTask, ls->tunnel);
        }
    }

    return ERR_OK;
}

void ptcArmUdpIdleOnOwnerThread(ptc_lstate_t *ls)
{
    if (ls->kind != kPtcLineKindUdp)
    {
        return;
    }

    ptc_tstate_t *ts  = tunnelGetState(ls->tunnel);
    uint64_t      now = wloopNowMS(getWorkerLoop(lineGetWID(ls->line)));

    ls->udp_idle_deadline_ms = now + ts->udp_idle_timeout_ms;
    if (! ls->udp_idle_scheduled)
    {
        ls->udp_idle_scheduled = true;
        lineScheduleDelayedTask(ls->line, ptcUdpIdleTask, ts->udp_idle_timeout_ms, ls->tunnel);
    }
}

bool ptcEnsureNextInit(tunnel_t *t, line_t *l, ptc_lstate_t *ls)
{
    if (ls->next_init_sent)
    {
        return true;
    }

    ls->next_init_sent = true;
    return withLineLocked(l, tunnelNextUpStreamInit, t);
}

void ptcOpenLineTask(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *ls = lineGetState(l, t);

    discard ptcEnsureNextInit(t, l, ls);
}

void ptcDeliverPayloadTask(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    buffer_pool_t *pool     = lineGetBufferPool(l);
    ptc_lstate_t  *ls       = lineGetState(l, t);
    uint32_t       tcp_read = sbufGetLength(buf);

    if (! ptcEnsureNextInit(t, l, ls))
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }

    ls = lineGetState(l, t);

    if (ls->kind == kPtcLineKindUdp)
    {
        ptcArmUdpIdleOnOwnerThread(ls);
        if (ls->read_paused)
        {
            lineReuseBuffer(l, buf);
            return;
        }
    }

    if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf))
    {
        return;
    }

    ls = lineGetState(l, t);

    if (ls->kind == kPtcLineKindTcp)
    {
        if (ls->read_paused)
        {
            ls->read_paused_len += tcp_read;
            return;
        }

        LOCK_TCPIP_CORE();
        if (ls->tcp_pcb != NULL)
        {
            tcp_recved(ls->tcp_pcb, tcp_read);
        }
        UNLOCK_TCPIP_CORE();
    }
}

void ptcCloseLineFromNetwork(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineLock(l);

    ptc_lstate_t *ls = lineGetState(l, t);

    LOCK_TCPIP_CORE();
    if (ls->kind == kPtcLineKindTcp && ls->tcp_pcb != NULL)
    {
        struct tcp_pcb *pcb = ls->tcp_pcb;
        ptcDetachTcpPcbLocked(ls);
        if (tcp_close(pcb) != ERR_OK)
        {
            tcp_abort(pcb);
        }
    }
    else if (ls->kind == kPtcLineKindUdp)
    {
        ptcDetachUdpFlowLocked(ls);
    }
    UNLOCK_TCPIP_CORE();

    const bool send_finish = ls->next_init_sent;
    ptcLinestateDestroy(ls);

    if (send_finish)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }

    lineUnlock(l);
}

void ptcCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    ptc_lstate_t *ls = lineGetState(l, t);

    LOCK_TCPIP_CORE();
    if (ls->kind == kPtcLineKindTcp && ls->tcp_pcb != NULL)
    {
        struct tcp_pcb *pcb = ls->tcp_pcb;
        ptcFlushWriteQueue(ls);
        ptcDetachTcpPcbLocked(ls);
        if (tcp_close(pcb) != ERR_OK)
        {
            tcp_abort(pcb);
        }
    }
    else if (ls->kind == kPtcLineKindUdp)
    {
        ptcDetachUdpFlowLocked(ls);
    }
    UNLOCK_TCPIP_CORE();

    ptcLinestateDestroy(ls);
    lineDestroy(l);
}

void ptcCloseLineTask(tunnel_t *t, line_t *l)
{
    ptcCloseLineFromNetwork(t, l);
}

void ptcResumeUpstreamTask(tunnel_t *t, line_t *l)
{
    discard withLineLocked(l, tunnelNextUpStreamResume, t);
}

void ptcUdpIdleTask(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *ls = lineGetState(l, t);

    if (ls->kind != kPtcLineKindUdp)
    {
        ls->udp_idle_scheduled = false;
        return;
    }

    uint64_t now = wloopNowMS(getWorkerLoop(lineGetWID(l)));
    if (now < ls->udp_idle_deadline_ms)
    {
        uint64_t remaining_ms = ls->udp_idle_deadline_ms - now;
        if (remaining_ms == 0)
        {
            remaining_ms = 1;
        }

        lineScheduleDelayedTask(l, ptcUdpIdleTask,
                                (remaining_ms > UINT32_MAX) ? UINT32_MAX : (uint32_t) remaining_ms, t);
        return;
    }

    ls->udp_idle_scheduled = false;
    ptcCloseLineFromNetwork(t, l);
}
