#include "structure.h"

#include "loggers/network_logger.h"

void lineStateInitialize(tcplistener_lstate_t * ls,wid_t wid)
{
    ls->data_queue   = bufferqueueCreate(wid);
}

void lineStateDestroy(tcplistener_lstate_t *ls)
{
    bufferqueueDestory(ls->data_queue);
}
