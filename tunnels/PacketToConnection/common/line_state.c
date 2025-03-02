#include "structure.h"

#include "loggers/network_logger.h"

void ptcLinestateInitialize(ptc_lstate_t *ls, wid_t wid, tunnel_t *t, line_t *l, void *pcb)
{
    ls->messages = 0;
    // this 1 lock will be freed when messages are 0 and line is destroyed
    lineLock(l);

    ls->data_queue = bufferqueueCreate(wid);

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

    if (ls->timer)
    {
        weventSetUserData(ls->timer, NULL);
        wtimerDelete(ls->timer);
    }
    bufferqueueDestory(ls->data_queue);

#ifdef DEBUG
    LOCK_TCPIP_CORE();
    assert(ls->tcp_pcb == NULL);
    assert(ls->messages == 0);
    UNLOCK_TCPIP_CORE();
#endif

    line_t *l = ls->line;
    memorySet(ls, 0, sizeof(ptc_lstate_t));
    lineUnlock(l);
}
