#include "structure.h"

#include "loggers/network_logger.h"


void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls)
{
    ls->pause_queue = bufferqueueCreate(kPauseQueueCapacity);
}

void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls)
{
    bufferqueueDestroy(&ls->pause_queue);
    if (ls->idle_handle)
    {
        LOGF("TcpConnector: idle item still exists for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }
    memoryZeroAligned32(ls, sizeof(tcpconnector_lstate_t));
}
