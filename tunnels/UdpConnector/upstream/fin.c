#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);
    wio_t                 *io = ls->io;

    if (UNLIKELY(io == NULL || wioIsClosed(io)))
    {
        LOGF("UdpConnector: upstream Finish reached an unavailable UDP socket");
        abortProgramNow(1);
    }

    local_idle_item_t *idle_item = ls->idle_handle;
    ls->idle_handle              = NULL;
    bool removed                 = localidletableRemoveIdleItem(udpconnectorGetLineIdleTable(ts, l), idle_item);
    if (! removed)
    {
        LOGF("UdpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    weventSetUserData(io, NULL);
    udpconnectorFlushWriteQueue(ls);
    udpconnectorLinestateDestroy(ls);
    wioClose(io);
}
