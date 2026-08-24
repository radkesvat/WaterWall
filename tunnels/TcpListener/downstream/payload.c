#include "structure.h"

#include "loggers/network_logger.h"

static void handleQueueOverflow(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls)
{
    LOGE("TcpListener: DownStream write queue overflow, size: %d , limit: %d",
         bufferqueueGetBufLen(&ls->pause_queue),
         kMaxPauseQueueSize);

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
    if (bufferqueueGetBufLen(&ls->pause_queue) > kMinPauseQueueSize)
    {
        tunnelNextUpStreamPause(t, l);
    }

    bufferqueuePushBack(&ls->pause_queue, buf);

    if (bufferqueueGetBufLen(&ls->pause_queue) > kMaxPauseQueueSize)
    {
        handleQueueOverflow(t, l, ts, ls);
    }
}

static void handleNormalWrite(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls, sbuf_t *buf)
{
    int bytes  = (int) sbufGetLength(buf);
    int nwrite = wioWrite(ls->io, buf);

    localidletableKeepIdleItemForAtleast(
        tcplistenerGetLineIdleTable(ts, l), ls->idle_handle, ts->active_idle_timeout_ms);

    if (nwrite >= 0 && nwrite < bytes)
    {
        ls->write_paused = true;
        wioSetCallBackWrite(ls->io, tcplistenerOnWriteComplete);
        tunnelNextUpStreamPause(t, l);
    }
}

void tcplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcplistener_tstate_t *ts = tunnelGetState(t);
    tcplistener_lstate_t *ls = lineGetState(l, t);

    if (ls->write_paused)
    {
        handlePausedWrite(t, l, ts, ls, buf);
    }
    else
    {
        handleNormalWrite(t, l, ts, ls, buf);
    }
}
