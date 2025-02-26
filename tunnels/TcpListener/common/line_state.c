#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerLinestateInitialize(tcplistener_lstate_t *ls, wid_t wid, wio_t *io, tunnel_t *t, line_t *l)
{
    ls->io           = io;
    ls->tunnel       = t;
    ls->line         = l;
    ls->write_paused = false;
    ls->established  = false;
    ls->data_queue   = bufferqueueCreate(wid);
}

void tcplistenerLinestateDestroy(tcplistener_lstate_t *ls)
{
    bufferqueueDestory(ls->data_queue);
    memorySet(ls, 0, sizeof(tcplistener_lstate_t));
}
