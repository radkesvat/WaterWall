#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls)
{
    ls->io          = NULL;
    ls->idle_handle = NULL;
    ls->read_paused = false;
    awqInit(&ls->write_queue, true);
}

void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls)
{
    awqDestroy(&ls->write_queue);
    if (ls->idle_handle)
    {
        LOGF("TcpConnector: idle item still exists for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcpconnector_lstate_t)));
}
