#include "structure.h"

#include "loggers/network_logger.h"

void ptcLinestateInitialize(ptc_lstate_t *ls, tunnel_t *t, line_t *l, ptc_line_kind_t kind, void *pcb)
{
    lineLock(l);

    memoryZeroAligned32(ls, sizeof(*ls));
    ls->tunnel      = t;
    ls->line        = l;
    ls->pause_queue = bufferqueueCreate(8);
    ls->ack_queue   = sbuf_ack_queue_t_with_capacity(8);
    ls->kind        = (uint8_t) kind;

    if (kind == kPtcLineKindTcp)
    {
        ls->tcp_pcb = pcb;
    }
    else if (kind == kPtcLineKindUdp)
    {
        ls->udp_pcb = pcb;
    }
}

void ptcLinestateDestroy(ptc_lstate_t *ls)
{
    wid_t   wid = lineGetWID(ls->line);
    line_t *l   = ls->line;

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pause_queue);

        c_foreach(i, sbuf_ack_queue_t, ls->ack_queue)
        {
            if ((*i.ref).buf == buf)
            {
                (*i.ref).buf = NULL;
            }
        }

        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
    }

    bufferqueueDestroy(&ls->pause_queue);

    c_foreach(i, sbuf_ack_queue_t, ls->ack_queue)
    {
        if ((*i.ref).buf != NULL)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), (*i.ref).buf);
        }
    }

    sbuf_ack_queue_t_drop(&ls->ack_queue);

#ifdef DEBUG
    LOCK_TCPIP_CORE();
    assert(ls->tcp_pcb == NULL);
    assert(ls->udp_pcb == NULL);
    assert(ls->route_ctx == NULL);
    UNLOCK_TCPIP_CORE();
#endif

    memoryZeroAligned32(ls, sizeof(ptc_lstate_t));
    lineUnlock(l);
}
