#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpconnector_lstate_t *ls = lineGetState(l, t);
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(ls->io == NULL || wioIsClosed(ls->io)))
    {
        LOGF("TcpConnector: upstream finish reached an unavailable TCP socket");
        abortProgramNow(1);
    }

    // This indicates that line is closed. Even if we get the closeCallback
    // while flushing the queue, no FIN will be sent to downstroam
    bool removed = localidletableRemoveIdleItemByHash(tcpconnectorGetLineIdleTable(ts, l), tcpconnectorIdleKey(ls->io));
    if (! removed)
    {
        LOGF("TcpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    ls->idle_handle = NULL; // mark as removed

    weventSetUserData(ls->io, NULL);

    tcpconnectorFlushWriteQueue(ls);

    wioClose(ls->io);

    tcpconnectorLinestateDestroy(ls);
}
