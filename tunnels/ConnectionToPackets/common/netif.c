#include "structure.h"

#include "loggers/network_logger.h"

/*
 * One emitted IPv4 packet on its way from lwIP to the chain's packet side.
 *
 * The netif output callback runs inside the owner engine, so it may
 * never call a neighboring tunnel. It copies the packet into an owned sbuf and
 * force-queues it to the selected packet worker instead - including when that
 * worker is the caller, so the boundary holds unconditionally. The same buffer
 * transfers onward; no lwIP storage escapes, and cancellation needs no pool.
 */
static void ctpEmitPacketDestroy(sbuf_t *buf, ctp_handoff_budget_t *budget)
{
    const size_t charge = sbufGetAllocationCharge(buf);
    sbufDestroy(buf);
    ctpHandoffRelease(budget, charge);
}

static void ctpEmitPacketCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg1;
    ctpEmitPacketDestroy(arg2, arg3);
}

static void ctpEmitPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    tunnel_t             *t      = arg1;
    sbuf_t               *buf    = arg2;
    ctp_handoff_budget_t *budget = arg3;

    // The message was delivered to exactly one worker; take the packet line from
    // that worker instead of re-reading thread-local state.
    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), worker->wid);

    // A packet queued before onQuiesceRequest() can still arrive after local
    // admission has closed. Do not extend it into a neighbouring callback.
    if (UNLIKELY(packet_line == NULL || ctpTunnelIsStopping(t)))
    {
        ctpEmitPacketDestroy(buf, budget);
        return;
    }

    ctpHandoffRelease(budget, sbufGetAllocationCharge(buf));

    /*
     * Hold admission across the callback. Shutdown
     * closes this gate and waits for admitted callbacks before stopping next.
     */
    if (UNLIKELY(! ctpNextGateEnter(t)))
    {
        bufferpoolReuseBuffer(lineGetBufferPool(packet_line), buf);
        return;
    }

#ifdef DEBUG
    lineRef(packet_line);
#endif

    tunnelNextUpStreamPayload(t, packet_line, buf);

#ifdef DEBUG
    if (! lineIsAlive(packet_line))
    {
        LOGF("ConnectionToPackets: packet line died during runtime, packet tunnel contract was violated");
        abortProgramNow(1);
    }

    lineUnref(packet_line);
#endif

    ctpNextGateLeave(t);
}

/*
 * Picks the packet worker for one emitted packet.
 *
 * Both directions of one flow must land on the same packet worker - a next node
 * that keeps per-flow state, PacketsToConnection included, pins that state to
 * the worker that first saw the flow - and the flow's own worker says nothing
 * about that: it was chosen by whoever accepted the application connection.
 * Deriving it from the packet, exactly like the packet devices do, is what makes
 * the two directions agree.
 *
 * Fragments are the exception the shared hash cannot handle. It falls back to
 * the IPv4 identification when the ports are missing, which is stable across one
 * datagram but different for every datagram of the same flow. So the affinity is
 * computed once, from the first fragment, with the fragment bits masked out of
 * the copy so it hashes identically to an unfragmented packet of that flow, and
 * the fragments that follow inherit it.
 *
 * Runs inside one non-reentrant owner engine, which makes the memo slot in the
 * netif context sufficient: ip4_frag() emits a whole datagram inside one
 * synchronous loop, so no other datagram can interleave on this netif.
 */
static wid_t ctpSelectPacketWorkerLocked(ctp_netif_ctx_t *ctx, uint8_t *packet, uint32_t len)
{
    wid_t packet_wid = ctx->wid;

    if (UNLIKELY(len < sizeof(struct ip_hdr)))
    {
        return packet_wid;
    }

    struct ip_hdr *iphdr        = (struct ip_hdr *) packet;
    const uint16_t offset_field = lwip_ntohs(IPH_OFFSET(iphdr));

    if ((offset_field & (IP_MF | IP_OFFMASK)) == 0)
    {
        ctx->frag_wid_valid = false;
        return deviceFlowAffineWID(packet, len, &packet_wid) ? packet_wid : ctx->wid;
    }

    const uint16_t ident = lwip_ntohs(IPH_ID(iphdr));

    if ((offset_field & IP_OFFMASK) != 0)
    {
        // A later fragment: reuse what the first one decided for this datagram.
        if (ctx->frag_wid_valid && ctx->frag_ident == ident)
        {
            return ctx->frag_wid;
        }
        return ctx->wid;
    }

    // Hash the first fragment as if it were whole, so it agrees with the
    // unfragmented packets of the same flow.
    IPH_OFFSET_SET(iphdr, 0);
    const bool hashed = deviceFlowAffineWID(packet, len, &packet_wid);
    IPH_OFFSET_SET(iphdr, lwip_htons(offset_field));

    ctx->frag_ident     = ident;
    ctx->frag_wid       = hashed ? packet_wid : ctx->wid;
    ctx->frag_wid_valid = true;
    return ctx->frag_wid;
}

err_t ctpNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    discard ipaddr;

    ctp_netif_ctx_t *ctx = netif->state;
    tunnel_t        *t   = ctx->tunnel;
    ctp_tstate_t    *ts  = tunnelGetState(t);
    assert(currentThreadOwnsWorker(ctx->wid));
    assert(ctx->engine == wwLwipEngineCurrent());

    /*
     * Owner teardown may emit while detaching objects; the stopping gate
     * prevents publication after node admission closes.
     */
    if (UNLIKELY(atomicLoadRelaxed(&ts->stopping)))
    {
        return ERR_IF;
    }

    if (UNLIKELY(p->tot_len == 0))
    {
        return ERR_VAL;
    }

    line_t *owner_packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), ctx->wid);
    assert(owner_packet_line != NULL && lineIsOnCurrentWorker(owner_packet_line));
    const uint16_t padding = bufferpoolGetLargeBufferPadding(lineGetBufferPool(owner_packet_line));
    uint32_t       capacity;
    size_t         charge;
    const bool     fits =
        sbufTryComputeCapacity(p->tot_len, padding, &capacity) && sbufTryComputeQueueCharge(capacity, &charge);
    if (UNLIKELY(! fits))
    {
        LOGF("ConnectionToPackets: output packet buffer geometry is unrepresentable");
        abortProgramNow(1);
    }
    if (! ctpHandoffReserve(ts->handoff_budget, charge, false))
        return ERR_MEM;
    /* Size detached output to the packet: a pooled small buffer would retain
     * several KiB even for a queued ACK. This replaces the old message allocation
     * while keeping all onward padding and avoiding a second payload copy. */
    sbuf_t *buf = sbufCreateWithPadding(p->tot_len, padding);
    assert(sbufGetAllocationCharge(buf) == charge);
    sbufSetLength(buf, p->tot_len);
    pbufLargeCopyToPtr(p, sbufGetMutablePtr(buf));

    const wid_t packet_wid = ctpSelectPacketWorkerLocked(ctx, sbufGetMutablePtr(buf), sbufGetLength(buf));

    if (sendWorkerMessageForceQueueWithCleanup(packet_wid,
                                               (WorkerMessageCallback) ctpEmitPacketOnWorker,
                                               ctpEmitPacketCleanup,
                                               ctx->tunnel,
                                               buf,
                                               ts->handoff_budget) != kWorkerMessageSubmitAccepted)
    {
        return ERR_MEM;
    }

    return ERR_OK;
}

static err_t ctpNetifInit(struct netif *netif)
{
    ctp_netif_ctx_t *ctx = netif->state;
    ctp_tstate_t    *ts  = tunnelGetState(ctx->tunnel);

    /*
     * No NETIF_FLAG_PRETEND here: that patch exists so a wildcard listener can
     * accept traffic addressed to somebody else. An actively opened client pcb
     * owns a concrete local address, and pretending would let this netif swallow
     * unrelated flows of any other lwIP user in the process.
     */
    netif->output = ctpNetifOutput;
    netif->mtu    = (u16_t) ts->mtu;
    netif->flags |= NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

ctp_netif_ctx_t *ctpEnsureNetifLocked(tunnel_t *t, wid_t wid)
{
    ctp_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    wwLwipEngineAssertCurrent();

    if (UNLIKELY(ts->netifs == NULL || wid >= ts->netifs_count))
    {
        return NULL;
    }

    if (ts->netifs[wid] != NULL)
    {
        assert(ts->netifs[wid]->engine == wwLwipEngineCurrent());
        return ts->netifs[wid];
    }

    ctp_netif_ctx_t *ctx = memoryAllocateZero(sizeof(ctp_netif_ctx_t));
    ctx->engine          = wwLwipEngineCurrent();
    ctx->tunnel          = t;
    ctx->wid             = wid;

    if (netif_add_noaddr(&ctx->netif, ctx, ctpNetifInit, ip_input) == NULL)
    {
        memoryFree(ctx);
        return NULL;
    }

    ip4_addr_t mask;
    ip4_addr_t gw;

    // A /32 with no gateway: this netif exists to own one virtual address and to
    // hand its packets to the chain, never to route a subnet.
    IP4_ADDR(&mask, 255, 255, 255, 255);
    ip4_addr_set_any(&gw);
    netif_set_addr(&ctx->netif, &ts->source_ip, &mask, &gw);

    netif_set_up(&ctx->netif);
    netif_set_link_up(&ctx->netif);

    ctx->added      = true;
    ts->netifs[wid] = ctx;
    return ctx;
}

void ctpDestroyWorkerNetif(tunnel_t *t, wid_t wid)
{
    ctp_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    if (ts->netifs == NULL)
        return;
    assert(wid < ts->netifs_count);
    ctp_netif_ctx_t *ctx = ts->netifs[wid];
    ts->netifs[wid]      = NULL;
    if (ctx == NULL)
        return;
    ww_lwip_engine_t *engine = ctx->engine;
    ww_lwip_engine_t *previous;
    const bool        entered = wwLwipEngineEnter(engine, &previous);
    assert(entered);
    discard entered;
    ctpTcpDrainDestroyNetif(ctx);
    if (ctx->added)
    {
        discard ip4_reass_purge_netif(&ctx->netif);
        netif_remove(&ctx->netif);
        ctx->added = false;
    }
    memoryFree(ctx);
    wwLwipEngineLeave(engine, previous);
}

void ctpDestroyLwipResources(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);
    if (ts->lwip_resources_destroyed)
        return;
    for (wid_t wid = 0; wid < ts->netifs_count; ++wid)
    {
        if ((ts->netifs != NULL && ts->netifs[wid] != NULL) ||
            (ts->active_lines != NULL && ts->active_lines[wid] != NULL))
        {
            LOGF("ConnectionToPackets: node stop preceded owner drain/Finish");
            abortProgramNow(1);
        }
    }
    assert(ts->drain_bytes == 0 && ts->drain_count == 0);
    if (ts->flow_registry_initialized)
    {
        /* Every engine's netif was purged by its owner before the Drained
         * barrier. Only detached routing records remain. */
        rwlockWriteLock(&ts->flows_lock);
        c_foreach(i, ctp_flow_map_t, ts->flows)
        {
            assert(i.ref->second.pcb == NULL && i.ref->second.lstate == NULL);
        }
        ctp_flow_map_t_clear(&ts->flows);
        ts->tomb_head = ts->tomb_count = 0;
        rwlockWriteUnlock(&ts->flows_lock);
    }
    ts->lwip_resources_destroyed = true;
}
