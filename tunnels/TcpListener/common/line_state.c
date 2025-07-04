#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerLinestateInitialize(tcplistener_lstate_t *ls, wio_t *io, tunnel_t *t, line_t *l)
{
    ls->io           = io;
    ls->tunnel       = t;
    ls->line         = l;
    ls->write_paused = false;
    ls->pause_queue   = bufferqueueCreate(kPauseQueueCapacity);
}

void tcplistenerLinestateDestroy(tcplistener_lstate_t *ls)
{
    bufferqueueDestory(&ls->pause_queue);
    memorySet(ls, 0, sizeof(tcplistener_lstate_t));
}
