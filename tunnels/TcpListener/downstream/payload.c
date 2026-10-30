#include "structure.h"

#include "loggers/network_logger.h"

static void handleQueueOverflow(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls)
{
    LOGE("TcpListener: write retention overflow, queued bytes: %zu, capacity charge: %zu, limit: %u",
         awqGetQueuedBytes(&ls->write_queue),
         awqGetUsage(&ls->write_queue).charge,
         (unsigned) kAwqMaxRetained);

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

void tcplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcplistener_tstate_t *ts = tunnelGetState(t);
    tcplistener_lstate_t *ls = lineGetState(l, t);

    tcplistenerApplyReadPreference(ls);
    awqRefreshPending(&ls->write_queue, wioGetWriteBufSize(ls->io));
    switch (awqAdmit(&ls->write_queue, lineGetBufferPool(l), &buf))
    {
    case kAwqOverflow:
        handleQueueOverflow(t, l, ts, ls);
        return;
    case kAwqQueuedPause:
        tunnelNextUpStreamPause(t, l);
        return;
    case kAwqQueued:
    case kAwqConsumed:
        return;
    case kAwqWriteNow:
        break;
    }

    const uint32_t bytes = sbufGetLength(buf);
    lineRef(l);
    const int nwrite = wioWrite(ls->io, buf);
    if (UNLIKELY(! lineIsAlive(l)))
    {
        lineUnref(l);
        return;
    }
    const awq_write_result_t result = awqAfterWrite(&ls->write_queue, nwrite, bytes, wioGetWriteBufSize(ls->io));
    if (LIKELY(result != kAwqWriteFailed))
    {
        localidletableKeepIdleItemForAtleast(
            tcplistenerGetLineIdleTable(ts, l), ls->idle_handle, ts->active_idle_timeout_ms);
        if (result == kAwqWriteBlocked)
        {
            const bool notify = awqTakePause(&ls->write_queue);
            wioSetCallBackWrite(ls->io, tcplistenerOnWriteComplete);
            if (notify)
                tunnelNextUpStreamPause(t, l);
        }
    }
    lineUnref(l);
}
