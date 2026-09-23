#include "structure.h"

#include "loggers/network_logger.h"

local_idle_table_t *tcpconnectorGetWorkerIdleTable(tcpconnector_tstate_t *ts)
{
    assert(ts != NULL);
    assert(ts->idle_tables != NULL);

    // Worker-local table: one checked identity for both the per-worker array and
    // the loop it is armed on. A non-event thread fails loudly instead of
    // silently creating a table on worker 0's loop.
    const wid_t wid = getCurrentEventWorkerWID();
    assert(wid < getWorkersCount());

    local_idle_table_t *table = ts->idle_tables[wid];
    if (table == NULL)
    {
        table                = localIdleTableCreate(getWorkerLoop(wid));
        ts->idle_tables[wid] = table;
    }

    return table;
}

local_idle_table_t *tcpconnectorGetLineIdleTable(tcpconnector_tstate_t *ts, line_t *l)
{
    assert(l != NULL);
    assert(lineIsOnCurrentEventWorker(l));
    discard l;
    return tcpconnectorGetWorkerIdleTable(ts);
}

void tcpconnectorOnClose(wio_t *io)
{
    tcpconnector_lstate_t *ls = (tcpconnector_lstate_t *) (weventGetUserdata(io));
    if (ls != NULL)
    {
        LOGD("TcpConnector: received close for FD:%x ", wioGetFD(io));
        weventSetUserData(ls->io, NULL);

        line_t                *l  = ls->line;
        tunnel_t              *t  = ls->tunnel;
        tcpconnector_tstate_t *ts = tunnelGetState(t);

        local_idle_item_t *idle_item = ls->idle_handle;
        ls->idle_handle              = NULL;
        bool removed                 = localidletableRemoveIdleItem(tcpconnectorGetLineIdleTable(ts, l), idle_item);
        if (! removed)
        {
            LOGF("TcpConnector: failed to remove idle item for FD:%x ", wioGetFD(io));
            abortProgramNow(1);
        }
        tcpconnectorLinestateDestroy(ls);

        tunnelPrevDownStreamFinish(t, l);
    }
    else
    {
        LOGD("TcpConnector: sent close for FD:%x ", wioGetFD(io));
    }
}

static void onRecv(wio_t *io, sbuf_t *buf)
{
    tcpconnector_lstate_t *lstate = weventGetUserdata(io);
    if (UNLIKELY(lstate == NULL))
    {
        bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        // assert(false);
        return;
    }
    tunnel_t              *t  = lstate->tunnel;
    line_t                *l  = lstate->line;
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    tcpconnector_lstate_t *ls = lineGetState(l, t);
    localidletableKeepIdleItemForAtleast(tcpconnectorGetLineIdleTable(ts, l), ls->idle_handle, kReadWriteTimeoutMs);

    tunnelPrevDownStreamPayload(t, l, buf);
}

static bool resumeWriteQueue(tcpconnector_lstate_t *lstate)
{
    line_t *line = lstate->line;
    wio_t  *io   = lstate->io;
    // Suppress synchronous WIO completion reentry until this FIFO drain yields.
    wioSetCallBackWrite(io, NULL);
    bufferbudgetReservationRelease(&lstate->active_write);
    while (bufferqueueGetBufCount(&lstate->pause_queue) > 0)
    {
        sbuf_t   *buf         = bufferqueuePopFrontReserved(&lstate->pause_queue, &lstate->active_write);
        const int bytes       = (int) sbufGetLength(buf);
        if (UNLIKELY(bytes == 0))
        {
            lineReuseBuffer(line, buf);
            bufferbudgetReservationRelease(&lstate->active_write);
            continue;
        }
        const int nwrite = wioWrite(io, buf);
        if (UNLIKELY(! lineIsAlive(line)))
            return false;
        tcpconnectorRefreshWriteBudget(lstate);
        if (UNLIKELY(nwrite < 0))
            return false;
        if (nwrite < bytes)
        {
            wioSetCallBackWrite(io, tcpconnectorOnWriteComplete);
            return false;
        }
        bufferbudgetReservationRelease(&lstate->active_write);
    }
    return true;
}

void tcpconnectorOnOutBoundConnected(wio_t *upstream_io)
{
    tcpconnector_lstate_t *lstate = weventGetUserdata(upstream_io);
    if (UNLIKELY(lstate == NULL))
    {
        // assert(false);
        return;
    }

    tunnel_t *t = lstate->tunnel;
    line_t   *l = lstate->line;
    wioSetCallBackRead(upstream_io, onRecv);

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGD("TcpConnector: connection succeed FD:%x [%s] => [%s]",
             wioGetFD(upstream_io),
             SOCKADDR_STR(wioGetLocaladdr(upstream_io), localaddrstr),
             SOCKADDR_STR(wioGetPeerAddr(upstream_io), peeraddrstr));
    }

    if (! lstate->read_paused)
    {
        if (UNLIKELY(wioRead(lstate->io) != 0))
        {
            return;
        }
    }

    lineRef(l);
    const bool drained = resumeWriteQueue(lstate);
    if (lineIsAlive(l))
    {
        if (drained)
            lstate->write_paused = false;
        // Transport readiness is independent of application write backpressure.
        tunnelPrevDownStreamEst(t, l);
        if (lineIsAlive(l) && drained && ! lstate->write_paused && lstate->queue_pause_sent)
        {
            lstate->queue_pause_sent = false;
            tunnelPrevDownStreamResume(t, l);
        }
    }
    lineUnref(l);
}

void tcpconnectorFlushWriteQueue(tcpconnector_lstate_t *lstate)
{
    assert(lstate->io != NULL && ! wioIsClosed(lstate->io));

    while (bufferqueueGetBufCount(&lstate->pause_queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&lstate->pause_queue);
        if (UNLIKELY(sbufGetLength(buf) == 0))
        {
            lineReuseBuffer(lstate->line, buf);
            continue;
        }
        wioWrite(lstate->io, buf);
    }
}

void tcpconnectorOnWriteComplete(wio_t *io)
{
    tcpconnector_lstate_t *ls = weventGetUserdata(io);
    if (ls == NULL)
        return;
    tcpconnectorRefreshWriteBudget(ls);
    if (! wioCheckWriteComplete(io))
        return;
    line_t   *line = ls->line;
    tunnel_t *t    = ls->tunnel;
    lineRef(line);
    if (resumeWriteQueue(ls) && lineIsAlive(line))
    {
        ls->write_paused     = false;
        const bool notify    = ls->queue_pause_sent;
        ls->queue_pause_sent = false;
        if (notify)
            tunnelPrevDownStreamResume(t, line);
    }
    lineUnref(line);
}

void tcpconnectorOnIdleConnectionExpire(local_idle_item_t *idle_tcp)
{
    tcpconnector_lstate_t *ls = idle_tcp->userdata;

    assert(ls != NULL && ls->tunnel != NULL);

    idle_tcp->userdata = NULL;
    ls->idle_handle    = NULL; // mark as removed

    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    LOGW("TcpConnector: expired 1 tcp connection on FD:%x ", wioGetFD(ls->io));
    weventSetUserData(ls->io, NULL);
    tcpconnectorFlushWriteQueue(ls);
    wioClose(ls->io);
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

void tcpconnectorRefreshWriteBudget(tcpconnector_lstate_t *ls)
{
    if (ls->active_write.budget != NULL)
    {
        // WIO owns the buffer, possibly already freed; only inspect its byte counter.
        bufferbudgetReservationSetBytes(&ls->active_write, wioGetWriteBufSize(ls->io));
    }
}
