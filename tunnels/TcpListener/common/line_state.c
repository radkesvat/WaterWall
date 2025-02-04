#include "structure.h"

#include "loggers/network_logger.h"

tcplistener_lstate_t *lineStateCreate(void)
{
    return NULL;
}

void lineStateDestroy(tcplistener_lstate_t *ls)
{
    bufferqueueDestory(ls->data_queue);
}
