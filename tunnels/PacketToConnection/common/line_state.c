#include "structure.h"

#include "loggers/network_logger.h"

void ptcLinestateInitialize(ptc_lstate_t *ls, wid_t wid, tunnel_t *t, line_t *l, void *pcb)
{
    ls->data_queue = bufferqueueCreate(wid);
    mutexInit(&ls->lock);

    ls->tunnel  = t;
    ls->line    = l;
    ls->tcp_pcb = pcb;

    ls->direct_stack = false;
    ls->write_paused = false;
    ls->read_paused  = false;
    ls->established  = false;
    ls->is_closing   = false;
}

void ptcLinestateDestroy(ptc_lstate_t *ls)
{
    assert(ls->tcp_pcb == NULL);
    assert(ls->direct_stack == false);
    
    if(ls->timer)
    {
        weventSetUserData(ls->timer, NULL);
        wtimerDelete(ls->timer);
    }

    bufferqueueDestory(ls->data_queue);
    memorySet(ls, 0, sizeof(ptc_lstate_t));
    mutexDestroy(&ls->lock);
}
