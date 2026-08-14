#include "structure.h"

#include "loggers/network_logger.h"

struct udp_pcb *ctpUdpDetachCallbacksLocked(ctp_lstate_t *ls)
{
    struct udp_pcb *pcb = ls->udp_pcb;

    if (pcb == NULL)
    {
        return NULL;
    }

    udp_recv(pcb, NULL, NULL);
    ls->udp_pcb = NULL;
    return pcb;
}

bool ctpUdpOpenFlow(tunnel_t *t, line_t *l, ctp_lstate_t *ls, const ip_addr_t *dest_ip, uint16_t dest_port)
{
    ctp_tstate_t   *ts  = tunnelGetState(t);
    struct udp_pcb *pcb = NULL;
    bool            ok  = false;

    LOCK_TCPIP_CORE();

    if (UNLIKELY(atomicLoadRelaxed(&ts->stopping)))
    {
        goto done;
    }

    ctp_netif_ctx_t *ctx = ctpEnsureNetifLocked(t, lineGetWID(l));
    if (ctx == NULL)
    {
        LOGE("ConnectionToPackets: could not create the virtual netif for worker %d", workerWIDForLog(lineGetWID(l)));
        goto done;
    }

    pcb = udp_new_ip_type(IPADDR_TYPE_V4);
    if (pcb == NULL)
    {
        LOGE("ConnectionToPackets: out of lwIP UDP pcbs, closing this flow");
        goto done;
    }

    ip_addr_t local_ip;
    ipAddrCopyFromIp4(local_ip, ts->source_ip);

    if (udp_bind_netif(pcb, &ctx->netif) != ERR_OK)
    {
        LOGE("ConnectionToPackets: virtual netif is being removed");
        goto done;
    }

    if (udp_bind(pcb, &local_ip, 0) != ERR_OK)
    {
        LOGE("ConnectionToPackets: could not bind a local port for the virtual source address");
        goto done;
    }

    // A connected pcb both fixes the destination of udp_send() and filters
    // inbound datagrams down to this one peer.
    if (udp_connect(pcb, dest_ip, dest_port) != ERR_OK)
    {
        LOGE("ConnectionToPackets: lwIP refused the UDP connect");
        goto done;
    }

    ls->udp_pcb  = pcb;
    ls->flow_key = (ctp_flow_key_t) {
        .remote_addr_network = ip_2_ip4(dest_ip)->addr,
        .local_addr_network  = ip4_addr_get_u32(&ts->source_ip),
        .remote_port         = dest_port,
        .local_port          = pcb->local_port,
        .protocol            = IP_PROTO_UDP,
    };

    if (! ctpFlowRegister(t, ls, pcb, IP_PROTO_UDP))
    {
        ls->udp_pcb = NULL;
        goto done;
    }

    udp_recv(pcb, ctpUdpRecvCallback, ls);

    pcb = NULL; // ownership stays with the flow
    ok  = true;

done:
    if (pcb != NULL)
    {
        udp_remove(pcb);
    }
    UNLOCK_TCPIP_CORE();
    return ok;
}

static bool ctpUdpShouldLogDrop(line_t *l, ctp_lstate_t *ls)
{
    const uint64_t now = wloopNowMS(getWorkerLoop(lineGetWID(l)));

    if (now - ls->last_drop_log_ms < (uint64_t) kCtpDropLogIntervalMs)
    {
        return false;
    }

    ls->last_drop_log_ms = now;
    return true;
}

/*
 * A datagram larger than one MTU is handed to lwIP whole and comes back out of
 * ctpNetifOutput() as a chain of IPv4 fragments, because ip4_output_if() splits
 * anything above netif->mtu. Building the fragments here would duplicate that
 * and get the identification field wrong.
 *
 * The buffer the payload is copied into is chosen by size rather than always
 * being PBUF_RAM: a PBUF_RAM allocation is one contiguous block from lwIP's
 * pooled heap, whose largest class cannot hold a maximum-size datagram at all,
 * while PBUF_POOL chains fixed-size buffers and scales all the way up.
 */
void ctpUdpSendPayload(tunnel_t *t, line_t *l, ctp_lstate_t *ls, sbuf_t *buf)
{
    ctp_tstate_t  *ts      = tunnelGetState(t);
    const uint32_t buf_len = sbufGetLength(buf);

    // Not an MTU question: a longer payload has no valid IPv4 UDP encoding, and
    // the u16_t casts below would silently truncate it.
    if (UNLIKELY(buf_len > (uint32_t) kCtpMaxUdpPayload))
    {
        if (ctpUdpShouldLogDrop(l, ls))
        {
            LOGW("ConnectionToPackets: dropping a %u byte datagram, an IPv4 UDP payload cannot exceed %u bytes",
                 (unsigned int) buf_len,
                 (unsigned int) kCtpMaxUdpPayload);
        }

        lineReuseBuffer(l, buf);
        return;
    }

    const pbuf_type type        = (buf_len + (uint32_t) kCtpUdpHeaderOverhead <= ts->mtu) ? PBUF_RAM : PBUF_POOL;
    err_t           send_result = ERR_OK;
    bool            allocated   = true;

    LOCK_TCPIP_CORE();

    if (! atomicLoadRelaxed(&ts->stopping) && ls->udp_pcb != NULL)
    {
        // A zero-length datagram is valid UDP and reaches the peer as a header
        // with no payload, so it is sent rather than discarded.
        struct pbuf *p = pbufAlloc(PBUF_TRANSPORT, (u16_t) buf_len, type);

        if (p == NULL)
        {
            allocated = false;
        }
        else
        {
            if (buf_len > 0)
            {
                send_result = pbuf_take(p, sbufGetMutablePtr(buf), (u16_t) buf_len);
            }

            if (send_result == ERR_OK)
            {
                send_result = udp_send(ls->udp_pcb, p);
            }

            pbuf_free(p);
        }
    }

    UNLOCK_TCPIP_CORE();

    if (UNLIKELY(! allocated))
    {
        if (ctpUdpShouldLogDrop(l, ls))
        {
            LOGW("ConnectionToPackets: dropping a %u byte datagram, lwIP is out of pbufs", (unsigned int) buf_len);
        }
    }
    else if (UNLIKELY(send_result != ERR_OK))
    {
        // ERR_MEM here usually means the fragment buffers ip4_frag() needs could
        // not be allocated, which is a capacity signal rather than a peer error.
        if (ctpUdpShouldLogDrop(l, ls))
        {
            LOGW("ConnectionToPackets: lwIP refused a %u byte datagram with error %d",
                 (unsigned int) buf_len,
                 (int) send_result);
        }
    }

    lineReuseBuffer(l, buf);
}

void ctpUdpRecvCallback(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    discard addr;
    discard port;

    ctp_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kCtpLineKindUdp || ls->udp_pcb != upcb || p == NULL)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return;
    }

    line_t     *l         = ls->line;
    const wid_t owner_wid = lineGetWID(l);

    if (UNLIKELY(! currentThreadIsEventWorkerWID(owner_wid)))
    {
        // The read buffer would have to come from the owner's pool. Injection is
        // always posted to the owner, so this can only be a stray replay.
        LOGW("ConnectionToPackets: udp recv callback arrived on worker %d for a line owned by worker %d; dropping "
             "datagram",
             workerWIDForLog(getWID()),
             workerWIDForLog(owner_wid));
        pbuf_free(p);
        return;
    }

    if (ls->read_paused)
    {
        // Version 1 backpressure for UDP is intentionally lossy: queueing here
        // would grow without bound for a peer that never drains.
        LOGD("ConnectionToPackets: dropping a datagram while the previous node is paused");
        pbuf_free(p);
        return;
    }

    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = bufferpoolGetBestFit(pool, p->tot_len, bufferpoolGetLargeBufferPadding(pool));

    sbufSetLength(buf, p->tot_len);
    pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->tot_len, 0);
    pbuf_free(p);

    if (lineIsAlive(l))
    {
        /* UDP is intentionally lossy when the worker queue refuses admission. */
        discard lineScheduleTaskWithBuf(l, ctpDeliverPayloadTask, ls->tunnel, buf);
    }
    else
    {
        lineReuseBuffer(l, buf);
    }
}
