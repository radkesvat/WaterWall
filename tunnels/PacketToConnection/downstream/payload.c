#include "structure.h"

#include "loggers/network_logger.h"



static void retryTcpWriteTimerCb(wtimer_t *timer)
{
    ptc_lstate_t *lstate = weventGetUserdata(timer);
    if (lstate == NULL)
    {
        // timer is not valid, this should not be called AFAIK
        assert(false);
        return;
    }
    assert(lstate->write_paused);
    LOCK_TCPIP_CORE();
    if (lstate->is_closing)
    {
        // this means that the line is already closed, so we can safely ignore this
        // soon the finish callback will be called and the resources will be freed
        UNLOCK_TCPIP_CORE();
        return;
    }
    assert(lineIsAlive(lstate->line));

    ptcFlushWriteQueue(lstate);

    if (lstate->write_paused)
    {
        // see you soon
        wtimerReset(timer, kTcpWriteRetryTime);
    }
    else
    {
        // bye bye
        lstate->timer = NULL;
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
    UNLOCK_TCPIP_CORE();
}

void ptcTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ptc_lstate_t *lstate = (ptc_lstate_t *) lineGetState(l, t);
    wid_t         wid    = lineGetWID(l);

    bool unlock_core = false;
    if (! lstate->stack_owned_locked && ! lstate->local_locked)
    {
        // we are on a different worker thread, so we must lock the tcpip mutex
        LOCK_TCPIP_CORE();

        if (! lineIsAlive(l))
        {
            assert(atomicLoadRelaxed(&lstate->messages) > 0);
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            UNLOCK_TCPIP_CORE();
            return;
        }
        unlock_core = true;
    }

    /*
        when tcpip stack is locked, our line will not be closed, so we can safely use it
        so, locking the line mutex is not necessary
    */

    if (lstate->is_closing)
    {
        assert(! lstate->stack_owned_locked); // impossible to be closing on direct stack

        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        goto return_unlockifneeded;
        return;
    }

    if (lstate->is_tcp)
    {
        struct tcp_pcb *tpcb = lstate->tcp_pcb;

        if (lstate->write_paused)
        {
            tunnelNextUpStreamPause(t, l);
            bufferqueuePush(lstate->data_queue, buf);
            goto return_unlockifneeded;
        }

        if (sbufGetLength(buf) > tcp_sndbuf(tpcb))
        {
            //  tcp_sndbuf is full
            lstate->write_paused = true;
            tunnelNextUpStreamPause(t, l);
            bufferqueuePush(lstate->data_queue, buf);
            assert(lstate->timer == NULL);
            lstate->timer = wtimerAdd(getWorkerLoop(wid), retryTcpWriteTimerCb, kTcpWriteRetryTime, 0);
            weventSetUserData(lstate->timer, lstate);
            goto return_unlockifneeded;
        }
        err_t error_code = tcp_write(tpcb, sbufGetMutablePtr(buf), sbufGetLength(buf), TCP_WRITE_FLAG_COPY);
        if (error_code != ERR_OK)
        {
            assert(false);
            LOGW("PacketToConnection: tcp_write failed, this is unexpected since we checked the memory status! , code: "
                 "%d",
                 error_code);
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);

            goto return_unlockifneeded;
        }

        /*
          lwip says:
           * To prompt the system to send data now, call tcp_output() after
           * calling tcp_write().
        */
        tcp_output(tpcb);
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
    }
    else
    {
        struct pbuf *p = pbufAlloc(PBUF_RAW, sbufGetLength(buf), PBUF_REF);

        p->payload = &buf->buf[0];

        // since PBUF_REF is used, lwip wont delay this buffer after call stack, if it needs queue then it will be
        // duplicated so we can free it now
        err_t error_code = udp_sendto(lstate->udp_pcb, p, &lstate->udp_pcb->remote_ip, lstate->udp_pcb->remote_port);
        if (error_code != ERR_OK)
        {
            LOGD("PacketToConnection: udp_sendto failed code: %d", error_code);
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);

            goto return_unlockifneeded;
        }
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
    }

return_unlockifneeded:
    if (unlock_core)
    {
        UNLOCK_TCPIP_CORE();
    }
}
