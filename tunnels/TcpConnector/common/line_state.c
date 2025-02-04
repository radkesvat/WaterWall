#include "structure.h"

#include "loggers/network_logger.h"


void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls, wid_t wid)
{
    ls->data_queue = bufferqueueCreate(wid);
}

void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls)
{
    bufferqueueDestory(ls->data_queue);
    memorySet(ls, 0, sizeof(tcpconnector_lstate_t));
}
