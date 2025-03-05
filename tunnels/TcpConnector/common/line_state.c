#include "structure.h"

#include "loggers/network_logger.h"


void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls)
{
    ls->pause_queue = bufferqueueCreate(kPauseQueueCapacity);
}

void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls)
{
    bufferqueueDestory(&ls->pause_queue);
    memorySet(ls, 0, sizeof(tcpconnector_lstate_t));
}
