#include "structure.h"

#include "loggers/network_logger.h"

static void handleQueueOverflow(tunnel_t *t, line_t *l, tcpconnector_tstate_t *ts, tcpconnector_lstate_t *ls)
{
    LOGE("TcpConnector: Upstream write queue overflow, size: %d , limit: %d", 
         bufferqueueLen(&ls->pause_queue), kMaxPauseQueueSize);

    bool removed = idleTableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, wioGetFD(ls->io));
    if (!removed)
    {
        LOGF("TcpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }

    ls->idle_handle = NULL;
    weventSetUserData(ls->io, NULL);
    wioClose(ls->io);
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

static void handlePausedWrite(tunnel_t *t, line_t *l, tcpconnector_tstate_t *ts, tcpconnector_lstate_t *ls, sbuf_t *buf)
{
    tunnelPrevDownStreamPause(t, l);
    bufferqueuePush(&ls->pause_queue, buf);

    if (bufferqueueLen(&ls->pause_queue) > kMaxPauseQueueSize)
    {
        handleQueueOverflow(t, l, ts, ls);
    }
}

static void handleNormalWrite(tunnel_t *t, line_t *l, tcpconnector_tstate_t *ts, tcpconnector_lstate_t *ls, sbuf_t *buf)
{
    int bytes = (int) sbufGetLength(buf);
    int nwrite = wioWrite(ls->io, buf);

    idleTableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kReadWriteTimeoutMs);

    if (nwrite >= 0 && nwrite < bytes)
    {
        ls->write_paused = true;
        wioSetCallBackWrite(ls->io, tcpconnectorOnWriteComplete);
        tunnelPrevDownStreamPause(t, l);
    }
}

void tcpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    tcpconnector_lstate_t *ls = lineGetState(l, t);

    if (ls->write_paused)
    {
        handlePausedWrite(t, l, ts, ls, buf);
    }
    else
    {
        handleNormalWrite(t, l, ts, ls, buf);
    }
}
