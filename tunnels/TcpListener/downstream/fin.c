#include "TcpAdapterCommon/close_linger.h"
#include "loggers/network_logger.h"
#include "structure.h"

void tcplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{

    tcplistener_tstate_t *ts = tunnelGetState(t);
    tcplistener_lstate_t *ls = lineGetState(l, t);

    // This indicates that line is closed. Even if we get the closeCallback
    // while flushing the queue, no FIN will be sent to upstream
    local_idle_table_t *table     = tcplistenerGetLineIdleTable(ts, l);
    local_idle_item_t  *idle_item = ls->idle_handle;
    ls->idle_handle               = NULL;
    bool removed                  = localidletableRemoveIdleItem(table, idle_item);
    if (! removed)
    {
        LOGF("TcpListener: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    weventSetUserData(ls->io, NULL);
    wioSetCallBackWrite(ls->io, NULL);

    tcplistenerFlushWriteQueue(ls);
    if (atomicLoadRelaxed(&ts->stopping) || ! tcpAdapterShouldLingerOnClose(l, ts->linger_on_normal_close) ||
        ! tcpAdapterBeginCloseLinger(ls->io, table))
        wioClose(ls->io);
    tcplistenerLinestateDestroy(ls);
    lineDestroy(l);
}
