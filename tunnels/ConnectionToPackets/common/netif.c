#include "structure.h"

#include "loggers/network_logger.h"

// Kept below the logger include: device_flow_affinity.h pulls in the internal
// logger, and the first logger a translation unit sees owns every LOGx in it.
#include "devices/device_flow_affinity.h"

/*
 * One emitted IPv4 packet on its way from lwIP to the chain's packet side.
 *
 * The netif output callback always runs with the lwIP core lock held, so it may
 * never call a neighboring tunnel. It copies the packet into this message and
 * force-queues it to the selected packet worker instead - including when that
 * worker is the caller, so the boundary holds unconditionally.
 */
typedef struct ctp_packet_emit_msg_s
{
    uint32_t len;
    uint8_t  data[];
} ctp_packet_emit_msg_t;

static void ctpEmitPacketCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg1;
    discard arg3;
    memoryFree(arg2);
}

static void ctpEmitPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg3;

    tunnel_t              *t          = arg1;
    ctp_packet_emit_msg_t *packet_msg = arg2;

    // The message was delivered to exactly one worker; take the packet line from
    // that worker instead of re-reading thread-local state.
    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), worker->wid);

    // A packet queued before onQuiesceRequest() can still arrive after local
    // admission has closed. Do not extend it into a neighbouring callback.
    if (UNLIKELY(packet_line == NULL || ctpTunnelIsStopping(t)))
    {
        memoryFree(packet_msg);
        return;
    }

    buffer_pool_t *pool = lineGetBufferPool(packet_line);
    sbuf_t        *buf  = bufferpoolGetBestFit(pool, packet_msg->len, bufferpoolGetLargeBufferPadding(pool));

    sbufSetLength(buf, packet_msg->len);
    memoryCopy(sbufGetMutablePtr(buf), packet_msg->data, packet_msg->len);
    memoryFree(packet_msg);

    /*
     * Rechecked after the allocation, which can wait on the pool. The gate is not
     * a strict quiescence barrier, but narrowing the window to the call itself is
     * what keeps an emitted packet from arriving at the next node after that
     * node's onStop() has already run.
     */
    if (UNLIKELY(! ctpNextGateEnter(t)))
    {
        bufferpoolReuseBuffer(pool, buf);
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
 * Runs with the core lock held, which is what makes the single memo slot in the
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

    /*
     * Reached with the core lock held. Stop already detached everything it owns
     * under that same lock, so a late output has nothing left to publish.
     */
    if (UNLIKELY(atomicLoadRelaxed(&ts->stopping)))
    {
        return ERR_IF;
    }

    if (UNLIKELY(p->tot_len == 0))
    {
        return ERR_VAL;
    }

    ctp_packet_emit_msg_t *packet_msg = memoryAllocate(sizeof(*packet_msg) + p->tot_len);
    if (UNLIKELY(packet_msg == NULL))
    {
        return ERR_MEM;
    }

    packet_msg->len = p->tot_len;
    pbufLargeCopyToPtr(p, packet_msg->data);

    const wid_t packet_wid = ctpSelectPacketWorkerLocked(ctx, packet_msg->data, packet_msg->len);

    WW_WORKER_MESSAGE_BENCHMARK_RECORD_CONTINUATION(kWorkerMessageBenchmarkContinuationBridgeRetryOrDelivery);
    if (sendWorkerMessageForceQueueWithCleanup(packet_wid,
                                               (WorkerMessageCallback) ctpEmitPacketOnWorker,
                                               ctpEmitPacketCleanup,
                                               ctx->tunnel,
                                               packet_msg,
                                               NULL) != kWorkerMessageSubmitAccepted)
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

    if (UNLIKELY(ts->netifs == NULL || wid >= ts->netifs_count))
    {
        return NULL;
    }

    if (ts->netifs[wid] != NULL)
    {
        return ts->netifs[wid];
    }

    ctp_netif_ctx_t *ctx = memoryAllocateZero(sizeof(ctp_netif_ctx_t));
    if (ctx == NULL)
    {
        return NULL;
    }

    ctx->tunnel = t;
    ctx->wid    = wid;

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

void ctpDestroyLwipResources(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    if (ts->lwip_resources_destroyed)
    {
        return;
    }

    LOCK_TCPIP_CORE();

    if (ts->flow_registry_initialized)
    {
        ctpFlowDropAllLocked(t);

        // Every draining pcb was registered, so the sweep above has already closed or
        // aborted it and cleared its callbacks; only the drain objects are left.
        ctpTcpDrainDestroyAllLocked(t);
    }

    if (ts->netifs != NULL)
    {
        for (wid_t wid = 0; wid < ts->netifs_count; ++wid)
        {
            ctp_netif_ctx_t *ctx = ts->netifs[wid];
            if (ctx == NULL)
            {
                continue;
            }

            if (ctx->added)
            {
                /*
                 * Reassembly state is process-global and keyed by the netif's
                 * one-byte index, so it has to go before netif_remove() makes
                 * that index available to an unrelated future interface.
                 *
                 * netif_remove() now does this itself; the call is kept so this
                 * teardown does not silently depend on that, and purging twice
                 * is a walk of a list that is already empty.
                 */
                discard ip4_reass_purge_netif(&ctx->netif);
            }
        }
    }

    if (ts->flow_registry_initialized)
    {
        rwlockWriteLock(&ts->flows_lock);
        ctpFragClearAfterNetifPurgeLocked(t);
        rwlockWriteUnlock(&ts->flows_lock);
    }

    if (ts->netifs != NULL)
    {
        for (wid_t wid = 0; wid < ts->netifs_count; ++wid)
        {
            ctp_netif_ctx_t *ctx = ts->netifs[wid];
            if (ctx == NULL)
            {
                continue;
            }
            if (ctx->added)
            {
                netif_remove(&ctx->netif);
                ctx->added = false;
            }
            memoryFree(ctx);
            ts->netifs[wid] = NULL;
        }
    }

    ts->lwip_resources_destroyed = true;
    UNLOCK_TCPIP_CORE();
}
