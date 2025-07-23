#include "loggers/network_logger.h"
#include "structure.h"

void tcplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{

    tcplistener_tstate_t *ts = tunnelGetState(t);
    tcplistener_lstate_t *ls = lineGetState(l, t);

    // This indicates that line is closed. Even if we get the closeCallback
    // while flushing the queue, no FIN will be sent to upstream
    bool removed = idleTableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, wioGetFD(ls->io));
    if (! removed)
    {
        LOGF("TcpListener: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }
    ls->idle_handle = NULL; // mark as removed
    weventSetUserData(ls->io, NULL);

    tcplistenerFlushWriteQueue(ls);
    wioClose(ls->io);
    tcplistenerLinestateDestroy(ls);
    lineDestroy(l);
}
