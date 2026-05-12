#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ptc_lstate_t *ls           = lineGetState(l, t);
    bool          send_pause   = false;
    bool          reuse_buffer = false;

    assert(lineIsAlive(l));

    if (ls->kind == kPtcLineKindUdp)
    {
        ptcArmUdpIdleOnOwnerThread(ls);
    }

    LOCK_TCPIP_CORE();

    if (ls->kind == kPtcLineKindTcp)
    {
        if (ls->tcp_pcb == NULL)
        {
            reuse_buffer = true;
        }
        else
        {
            struct tcp_pcb *tpcb      = ls->tcp_pcb;
            const uint32_t  buf_len   = sbufGetLength(buf);
            const uint16_t  available = tcp_sndbuf(tpcb);

            sbuf_ack_queue_t_push_back(&ls->ack_queue, ((sbuf_ack_t) {.buf = buf, .written = 0, .total = buf_len}));

            if (ls->write_paused || available == 0)
            {
                ls->write_paused = true;
                bufferqueuePushBack(&ls->pause_queue, buf);
                send_pause = true;
            }
            else
            {
                const uint16_t write_len = (uint16_t) min((uint32_t) available, buf_len);
                const err_t    err       = tcp_write(tpcb, sbufGetMutablePtr(buf), write_len, TCP_WRITE_FLAG_COPY);

                if (err != ERR_OK)
                {
                    ls->write_paused = true;
                    bufferqueuePushBack(&ls->pause_queue, buf);
                    send_pause = true;
                }
                else
                {
                    tcp_output(tpcb);

                    if (write_len != buf_len)
                    {
                        sbufShiftRight(buf, write_len);
                        ls->write_paused = true;
                        bufferqueuePushBack(&ls->pause_queue, buf);
                        send_pause = true;
                    }
                }
            }
        }
    }
    else
    {
        if (ls->udp_pcb == NULL)
        {
            reuse_buffer = true;
        }
        else
        {
            struct pbuf *p = pbufAlloc(PBUF_TRANSPORT, sbufGetLength(buf), PBUF_POOL);

            if (p == NULL || pbuf_take(p, sbufGetMutablePtr(buf), sbufGetLength(buf)) != ERR_OK)
            {
                if (p != NULL)
                {
                    pbuf_free(p);
                }
                reuse_buffer = true;
            }
            else
            {
                discard udp_sendfrom(ls->udp_pcb, p, &ls->udp_local_addr, ls->udp_local_port);
                pbuf_free(p);
                reuse_buffer = true;
            }
        }
    }

    UNLOCK_TCPIP_CORE();

    if (reuse_buffer)
    {
        lineReuseBuffer(l, buf);
    }

    if (send_pause)
    {
        (void) withLineLocked(l, tunnelNextUpStreamPause, t);
    }
}
