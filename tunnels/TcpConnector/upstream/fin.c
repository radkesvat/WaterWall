#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpconnector_lstate_t *ls = lineGetState(l, t);
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    // This indicates that line is closed. Even if we get the closeCallback
    // while flushing the queue, no FIN will be sent to downstroam
    bool removed = idleTableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, wioGetFD(ls->io));
    if (! removed)
    {
        LOGF("TcpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }
    ls->idle_handle = NULL; // mark as removed

    weventSetUserData(ls->io, NULL);

    tcpconnectorFlushWriteQueue(ls);

    wioClose(ls->io);

    tcpconnectorLinestateDestroy(ls);
}
