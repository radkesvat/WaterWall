#include "structure.h"

#include "loggers/network_logger.h"

void ptcLinestateInitialize(ptc_lstate_t *ls, wid_t wid, tunnel_t *t, line_t *l, void *pcb)
{
    ls->data_queue = bufferqueueCreate(wid);

    ls->tunnel  = t;
    ls->line    = l;
    ls->tcp_pcb = pcb;

    ls->stack_owned_locked = false;
    ls->write_paused = false;
    ls->read_paused  = false;
    ls->established  = false;
    ls->is_closing   = false;
}

void ptcLinestateDestroy(ptc_lstate_t *ls)
{
    assert(ls->tcp_pcb == NULL);
    
    if(ls->timer)
    {
        weventSetUserData(ls->timer, NULL);
        wtimerDelete(ls->timer);
    }

    bufferqueueDestory(ls->data_queue);
    memorySet(ls, 0, sizeof(ptc_lstate_t));
}
