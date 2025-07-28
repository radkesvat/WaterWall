#include "structure.h"

#include "loggers/network_logger.h"

// static void retryTcpWriteTimerCb(wtimer_t *timer)
// {
//     ptc_lstate_t *lstate = weventGetUserdata(timer);
//     assert(lineIsAlive(lstate->line));
//     if (lstate == NULL)
//     {
//         // timer is not valid, this should not be called AFAIK
//         assert(false);
//         return;
//     }

//     assert(lstate->write_paused);
//     LOCK_TCPIP_CORE();

//     if (! lstate->tcp_pcb)
//     {
//         // connection is closed
//         UNLOCK_TCPIP_CORE();
//         lstate->timer = NULL;
//         weventSetUserData(timer, NULL);
//         wtimerDelete(timer);
//         return;
//     }

//     ptcFlushWriteQueue(lstate);

//     if (lstate->write_paused)
//     {
//         // see you soon
//         wtimerReset(timer, kTcpWriteRetryTime);
//     }
//     else
//     {
//         // bye bye
//         lstate->timer = NULL;
//         weventSetUserData(timer, NULL);
//         wtimerDelete(timer);

//         tunnel_t *t = lstate->tunnel;
//         line_t   *l = lstate->line;
//         tunnelNextUpStreamResume(t, l);
//     }
//     // UNLOCK_TCPIP_CORE();
// }

void ptcTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ptc_lstate_t *lstate = (ptc_lstate_t *) lineGetState(l, t);
    wid_t         wid    = lineGetWID(l);

    assert(lineIsAlive(l));

    LOCK_TCPIP_CORE();

    if (! lstate->tcp_pcb)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        goto return_unlockifneeded;
    }

#if SHOW_ALL_LOGS
    printDebug("PacketToConnection: received %d bytes\n", sbufGetLength(buf));
#endif

    if (lstate->is_tcp)
    {
        struct tcp_pcb *tpcb = lstate->tcp_pcb;

        sbuf_ack_queue_t_push_back(&lstate->ack_queue, ((sbuf_ack_t){buf, 0, sbufGetLength(buf)}));
        
        if (lstate->write_paused)
        {
            tunnelNextUpStreamPause(t, l);
            bufferqueuePushBack(&lstate->pause_queue, buf);
            goto return_unlockifneeded;
        }
        int diff = tcp_sndbuf(tpcb) - sbufGetLength(buf);
        if (diff < 0)
        {

#if SHOW_ALL_LOGS
            LOGD("PacketToConnection: tcp_sndbuf is full, only writing %d from %d", tcp_sndbuf(tpcb),
                 sbufGetLength(buf));
#endif
            unsigned int len = tcp_sndbuf(tpcb);

            if (len > 0)
            {
                err_t error_code = tcp_write(tpcb, sbufGetMutablePtr(buf), len, 0);
                if (error_code == ERR_OK)
                {                    
                    sbufShiftRight(buf, len);
                    tcp_output(tpcb);
                }
            }

        pause:
            lstate->write_paused = true;
            tunnelNextUpStreamPause(t, l);
            bufferqueuePushBack(&lstate->pause_queue, buf);
            // assert(lstate->timer == NULL);
            // lstate->timer = wtimerAdd(getWorkerLoop(wid), retryTcpWriteTimerCb, kTcpWriteRetryTime, 0);
            // weventSetUserData(lstate->timer, lstate);
            goto return_unlockifneeded;
        }
        err_t error_code = tcp_write(tpcb, sbufGetMutablePtr(buf), sbufGetLength(buf), 0);
        if (error_code == ERR_OK)
        {
            //nothing
        }
        else
        {
            goto pause;
        }

        /*
          lwip says:
           * To prompt the system to send data now, call tcp_output() after
           * calling tcp_write().
        */
        tcp_output(tpcb);
    }
    else
    {
        struct pbuf *p = pbufAlloc(PBUF_RAW, sbufGetLength(buf), PBUF_POOL);

        pbuf_take(p, sbufGetMutablePtr(buf), sbufGetLength(buf));

        err_t error_code = udp_sendto(lstate->udp_pcb, p, &lstate->udp_pcb->remote_ip, lstate->udp_pcb->remote_port);
        if (error_code != ERR_OK)
        {

#if SHOW_ALL_LOGS
            LOGD("PacketToConnection: udp_sendto failed code: %d", error_code);
#endif

            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);

            goto return_unlockifneeded;
        }
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
    }

return_unlockifneeded:
    UNLOCK_TCPIP_CORE();
}
