#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerLinestateInitialize(tcplistener_lstate_t *ls, wio_t *io, tunnel_t *t, line_t *l)
{
    ls->io          = io;
    ls->tunnel      = t;
    ls->line        = l;
    ls->idle_handle = NULL;
    ls->read_paused = false;
    awqInit(&ls->write_queue, false);
}

void tcplistenerLinestateDestroy(tcplistener_lstate_t *ls)
{
    awqDestroy(&ls->write_queue);
    if (ls->idle_handle)
    {
        LOGF("TcpListener: idle item still exists for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcplistener_lstate_t)));
}
