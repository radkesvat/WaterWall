#include "structure.h"

#include "loggers/network_logger.h"


void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls)
{
    ls->pause_queue  = bufferqueueCreate(kPauseQueueCapacity);
    ls->io           = NULL;
    ls->idle_handle  = NULL;
    ls->dns_request  = NULL;
    ls->write_paused = false;
    ls->read_paused  = false;
    ls->resolving    = false;
}

void tcpconnectorCancelDnsRequest(tcpconnector_lstate_t *ls)
{
    if (ls->dns_request != NULL)
    {
        ls->dns_request->cancelled = true;
        ls->dns_request            = NULL;
    }
    ls->resolving = false;
}

void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls)
{
    tcpconnectorCancelDnsRequest(ls);
    bufferqueueDestroy(&ls->pause_queue);
    if (ls->idle_handle)
    {
        LOGF("TcpConnector: idle item still exists for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }
    memoryZeroAligned32(ls, sizeof(tcpconnector_lstate_t));
}
