#include "structure.h"

#include "TcpAdapterCommon/close_linger.h"

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
    // while flushing the queue, no FIN will be sent downstream.
    local_idle_table_t *table     = tcpconnectorGetLineIdleTable(ts, l);
    local_idle_item_t  *idle_item = ls->idle_handle;
    ls->idle_handle               = NULL;
    bool removed                  = localidletableRemoveIdleItem(table, idle_item);
    if (! removed)
    {
        LOGF("TcpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    weventSetUserData(ls->io, NULL);
    wioSetCallBackWrite(ls->io, NULL);

    tcpconnectorFlushWriteQueue(ls);

    if (! wioIsConnected(ls->io) || ! tcpAdapterShouldLingerOnClose(l, ts->linger_on_normal_close) ||
        ! tcpAdapterBeginCloseLinger(ls->io, table))
        wioClose(ls->io);

    tcpconnectorLinestateDestroy(ls);
}
