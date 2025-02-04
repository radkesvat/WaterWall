#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerLinestateInitialize(tcplistener_lstate_t *ls, wid_t wid)
{
    ls->data_queue = bufferqueueCreate(wid);
}

void tcplistenerLinestateDestroy(tcplistener_lstate_t *ls)
{
    bufferqueueDestory(ls->data_queue);
    memorySet(ls, 0, sizeof(tcplistener_lstate_t));
}
