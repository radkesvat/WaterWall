#include "structure.h"

#include "loggers/network_logger.h"

static void handleQueueOverflow(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls)
{
    LOGE("TcpListener: write retention overflow, queued bytes: %zu, capacity charge: %zu, limit: %u",
         bufferqueueGetBufLen(&ls->pause_queue),
         bufferbudgetGetUsage(&ls->write_budget).charge,
         (unsigned) kMaxPauseQueueSize);

    local_idle_item_t *idle_item = ls->idle_handle;
    ls->idle_handle              = NULL;
    bool removed                 = localidletableRemoveIdleItem(tcplistenerGetLineIdleTable(ts, l), idle_item);
    if (! removed)
    {
        LOGF("TcpListener: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    weventSetUserData(ls->io, NULL);
    wioClose(ls->io);
    tcplistenerLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    lineDestroy(l);
}

static void handlePausedWrite(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls, sbuf_t *buf)
{
    tcplistenerRefreshWriteBudget(ls);
    if (UNLIKELY(! bufferqueueTryPushBack(&ls->pause_queue, &buf)))
    {
        lineReuseBuffer(l, buf);
        handleQueueOverflow(t, l, ts, ls);
        return;
    }

    // Publish FIFO ownership, accounting and the latch before a nested Payload or Finish.
    if (! ls->queue_pause_sent && (bufferbudgetGetUsage(&ls->write_budget).bytes >= kMinPauseQueueSize ||
                                   bufferbudgetGetUsage(&ls->write_budget).charge >= kMinPauseQueueSize))
    {
        ls->queue_pause_sent = true;
        tunnelNextUpStreamPause(t, l);
    }
}

static void handleNormalWrite(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls, sbuf_t *buf)
{
    tcplistenerRefreshWriteBudget(ls);
    if (UNLIKELY(! bufferbudgetTryReserve(&ls->write_budget, buf, &ls->active_write)))
    {
        lineReuseBuffer(l, buf);
        handleQueueOverflow(t, l, ts, ls);
        return;
    }
    const int bytes = (int) sbufGetLength(buf);
    // Empty stream input owns no wire work and must not become a WIO disconnect.
    if (UNLIKELY(bytes == 0))
    {
        bufferbudgetReservationRelease(&ls->active_write);
        lineReuseBuffer(l, buf);
        return;
    }
    lineRef(l);
    const int nwrite = wioWrite(ls->io, buf);
    if (UNLIKELY(! lineIsAlive(l)))
    {
        lineUnref(l);
        return;
    }
    tcplistenerRefreshWriteBudget(ls);
    if (LIKELY(nwrite >= 0))
    {
        localidletableKeepIdleItemForAtleast(
            tcplistenerGetLineIdleTable(ts, l), ls->idle_handle, ts->active_idle_timeout_ms);
        if (nwrite < bytes)
        {
            ls->write_paused     = true;
            const bool notify    = ! ls->queue_pause_sent;
            ls->queue_pause_sent = true;
            wioSetCallBackWrite(ls->io, tcplistenerOnWriteComplete);
            if (notify)
                tunnelNextUpStreamPause(t, l);
        }
        else
        {
            bufferbudgetReservationRelease(&ls->active_write);
        }
    }
    lineUnref(l);
}

void tcplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcplistener_tstate_t *ts = tunnelGetState(t);
    tcplistener_lstate_t *ls = lineGetState(l, t);

    tcplistenerApplyReadPreference(ls);
    if (ls->write_paused)
    {
        handlePausedWrite(t, l, ts, ls, buf);
    }
    else
    {
        handleNormalWrite(t, l, ts, ls, buf);
    }
}
