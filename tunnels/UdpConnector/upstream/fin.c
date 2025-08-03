#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);
    wio_t                 *io = ls->io;

    bool removed = idletableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, wioGetFD(ls->io));
    if (! removed)
    {
        LOGF("UdpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }
    ls->idle_handle = NULL; // mark as removed

    weventSetUserData(io, NULL);
    udpconnectorLinestateDestroy(ls);
    wioClose(io);
}
