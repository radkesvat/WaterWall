#include "structure.h"

#include "loggers/network_logger.h"

static void localThreadPacketReceived(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    tunnel_t *t   = (tunnel_t *) arg1;
    sbuf_t   *buf = (sbuf_t *) arg2;
    discard   arg3;

    tunnelPrevDownStreamPayload(t, tunnelchainGetPacketLine(tunnelGetChain(t), worker->wid), buf);
}

void updateCheckSumTcp(u16_t *_hc, const void *_orig, const void *_new, int n)
{
    const u16_t *orig = _orig;
    const u16_t *new  = _new;
    u16_t hc          = ~*_hc;
    while (n--)
    {
        /* HC' = ~(~HC + ~m + m') */
        u32_t s;
        s = (u32_t) hc + ((~*orig) & 0xffff) + *new;
        while (s & 0xffff0000)
        {
            s = (s & 0xffff) + (s >> 16);
        }
        hc = (u16_t) s;
        orig++;
        new ++;
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
        *hc = 0xffff;
    }
}

err_t ptcNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    discard netif;
    discard ipaddr;
    discard p;

    // i this i should not play with the lock, i have no idea about the state of the tcpip thread
    // LWIP_ASSERT_CORE_LOCKED(); // test code , is it necessary?
    // UNLOCK_TCPIP_CORE();

    tunnel_t *t   = netif->state;
    wid_t     wid = getWID();
    //

    // create sbuf from pbuf and send it

    // if (UNLIKELY(p->next == NULL))
    // {
    //     sbuf_t *temp_buf = sbufCreateViewFromPbuf(p);
    //     if (temp_buf == NULL)
    //     {
    //         goto slow_path;
    //     }
    //     tunnelPrevDownStreamPayload(t, tunnelchainGetPacketLine(tunnelGetChain(t), wid), temp_buf);
    // }
// slow_path:;

    sbuf_t *buf;
    if (p->tot_len <= SMALL_BUFFER_SIZE)
    {
        buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(wid));
    }
    else
    {
        assert(false); // we send packet so this should not happen
        buf = bufferpoolGetLargeBuffer(getWorkerBufferPool(wid));
    }
    // printDebug("len is %d of %d \n",p->len, p->tot_len);

    sbufSetLength(buf, p->tot_len);

    // BENCH_BEGIN(ptcNetifOutput);
    pbufLargeCopyToPtr(p, sbufGetMutablePtr(buf));
    // BENCH_END(ptcNetifOutput);

     
    // BENCH_BEGIN(ptcNetifOutput2);
    // pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->tot_len, 0);
    // BENCH_END(ptcNetifOutput2);

    tunnelPrevDownStreamPayload(t, tunnelchainGetPacketLine(tunnelGetChain(t), wid), buf);
    return ERR_OK;

    // if (p->tot_len - p->len >= 128)
    // {
    //     memoryCopyLarge(sbufGetMutablePtr(buf), p->payload, p->tot_len);
    // }
    // else
    // {
    // pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->tot_len, 0);
    // }

    // localThreadPacketReceived(getNextDistributionWID(), localPacketReceived, t, buf, NULL);

    return ERR_OK;
}

void ptcFlushWriteQueue(ptc_lstate_t *lstate)
{

    struct tcp_pcb *tpcb = lstate->tcp_pcb;
    while (bufferqueueLen(&lstate->pause_queue) > 0)
    {
        sbuf_t *buf = bufferqueueFront(&lstate->pause_queue);

        // assert(sbufGetLength(buf) <= TCP_SND_BUF);
        int diff = tcp_sndbuf(tpcb) - sbufGetLength(buf);
        if (diff < 0)
        {
            unsigned int len = tcp_sndbuf(tpcb);
#if SHOW_ALL_LOGS
            LOGD("PacketToConnection: still full, writing %d bytes", len);
#endif

            if (len > 0)
            {
                err_t error_code = tcp_write(tpcb, sbufGetMutablePtr(buf), len, 0);
                if (error_code == ERR_OK)
                {
                    sbufShiftRight(buf, len);
                }
            }
            lstate->write_paused = true;
            tcp_output(tpcb);
            return;
        }

#if SHOW_ALL_LOGS
        LOGD("PacketToConnection: after a time, written a full %d bytes", sbufGetLength(buf));
#endif
        err_t error_code = tcp_write(tpcb, sbufGetMutablePtr(buf), sbufGetLength(buf), 0);

        if (error_code != ERR_OK)
        {
            lstate->write_paused = true;
            tcp_output(tpcb);
            return;
        }

        bufferqueuePopFront(&lstate->pause_queue); // pop to remove from queue
    }
    /*
      lwip says:
       * To prompt the system to send data now, call tcp_output() after
       * calling tcp_write().
    */
    tcp_output(tpcb);
    lstate->write_paused = false;
}

err_t ptcTcpSendCompleteCallback(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    // if(UNLIKELY(arg == NULL)){
    //     return ERR_OK;
    // }
    discard len;

    ptc_lstate_t *lstate = (ptc_lstate_t *) arg;

    if (lstate == NULL || tpcb == NULL)
    {
        // is not valid, this should not be called AFAIK
        assert(false);
        return ERR_OK;
    }
    assert(lineIsAlive(lstate->line));

    if (UNLIKELY(! lstate->tcp_pcb))
    {
        // connection is closed
        return ERR_OK;
    }
    wid_t wid = getWID();

    while (len > 0)
    {
        sbuf_ack_t *b_ack = (sbuf_ack_t *) sbuf_ack_queue_t_front(&lstate->ack_queue);
        u16_t       cost  = min(b_ack->total - b_ack->written, len);

        b_ack->written += cost;
        assert(len >= cost);
        len -= cost;

        if (b_ack->total == b_ack->written)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), b_ack->buf);
            sbuf_ack_queue_t_pop_front(&lstate->ack_queue);
        }
    }

    if (lstate->write_paused)
    {

        ptcFlushWriteQueue(lstate);
        if (! lstate->write_paused)
        {
            tunnelNextUpStreamResume(lstate->tunnel, lstate->line);
        }
    }

    return ERR_OK;
}
