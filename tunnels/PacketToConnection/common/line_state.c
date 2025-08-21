#include "structure.h"

#include "loggers/network_logger.h"

void ptcLinestateInitialize(ptc_lstate_t *ls, wid_t wid, tunnel_t *t, line_t *l, void *pcb)
{
    discard wid;

    ls->messages = 0;
    // this 1 lock will be freed when messages are 0 and line is destroyed
    lineLock(l);

    ls->pause_queue = bufferqueueCreate(8);
    ls->ack_queue   = sbuf_ack_queue_t_with_capacity(8);

    ls->tunnel  = t;
    ls->line    = l;
    ls->tcp_pcb = pcb;

    ls->write_paused = false;
    ls->read_paused  = false;
    ls->established  = false;
}

void ptcLinestateDestroy(ptc_lstate_t *ls)
{
    // dont call this before line is destroyed
    assert(! lineIsAlive(ls->line));

    wid_t wid = lineGetWID(ls->line);

    if (ls->timer)
    {
        weventSetUserData(ls->timer, NULL);
        wtimerDelete(ls->timer);
    }

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pause_queue);

        c_foreach(i, sbuf_ack_queue_t, ls->ack_queue)
        {
            if ((*i.ref).buf == buf)
            {
                // lazy remove from ack queue
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
    assert(ls->messages == 0);
    UNLOCK_TCPIP_CORE();
#endif

    line_t *l = ls->line;
    memoryZeroAligned32(ls, sizeof(ptc_lstate_t));
    lineUnlock(l);
}
