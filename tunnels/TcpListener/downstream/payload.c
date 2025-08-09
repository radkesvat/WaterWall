#include "structure.h"

#include "loggers/network_logger.h"


static void handleQueueOverflow(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls)
{
    LOGE("TcpListener: DownStream write queue overflow, size: %d , limit: %d", 
         bufferqueueGetBufLen(&ls->pause_queue), kMaxPauseQueueSize);

    bool removed = idletableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, wioGetFD(ls->io));
    if (!removed)
    {
        LOGF("TcpListener: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }

    ls->idle_handle = NULL;
    weventSetUserData(ls->io, NULL);
    wioClose(ls->io);
    tcplistenerLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    lineDestroy(l);
}

static void handlePausedWrite(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls, sbuf_t *buf)
{
    tunnelNextUpStreamPause(t, l);
    bufferqueuePushBack(&ls->pause_queue, buf);

    if (bufferqueueGetBufLen(&ls->pause_queue) > kMaxPauseQueueSize)
    {
        handleQueueOverflow(t, l, ts, ls);
    }
}

static void handleNormalWrite(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls, sbuf_t *buf)
{
    int bytes = (int) sbufGetLength(buf);
    int nwrite = wioWrite(ls->io, buf);

    idletableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kEstablishedKeepAliveTimeOutMs);

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
