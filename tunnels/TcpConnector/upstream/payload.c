#include "structure.h"

#include "loggers/network_logger.h"

static void handleQueueOverflow(tunnel_t *t, line_t *l, tcpconnector_tstate_t *ts, tcpconnector_lstate_t *ls)
{
    LOGE("TcpConnector: write retention overflow, queued bytes: %zu, capacity charge: %zu, limit: %u",
         awqGetQueuedBytes(&ls->write_queue),
         awqGetUsage(&ls->write_queue).charge,
         (unsigned) kAwqMaxRetained);

    /* Payload admission established the live socket; budget operations do not call out. */
    assert(ls->io != NULL);
    local_idle_item_t *idle_item = ls->idle_handle;
    ls->idle_handle              = NULL;
    bool removed                 = localidletableRemoveIdleItem(tcpconnectorGetLineIdleTable(ts, l), idle_item);
    if (! removed)
    {
        LOGF("TcpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    weventSetUserData(ls->io, NULL);
    wioClose(ls->io);

    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

void tcpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    tcpconnector_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->io == NULL || wioIsClosed(ls->io)))
    {
        LOGF("TcpConnector: upstream payload reached an unavailable TCP socket");
        abortProgramNow(1);
    }

    tcpconnectorApplyReadPreference(ls);
    awqRefreshPending(&ls->write_queue, wioGetWriteBufSize(ls->io));
    switch (awqAdmit(&ls->write_queue, lineGetBufferPool(l), &buf))
    {
    case kAwqOverflow:
        handleQueueOverflow(t, l, ts, ls);
        return;
    case kAwqQueuedPause:
        tunnelPrevDownStreamPause(t, l);
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
        localidletableKeepIdleItemForAtleast(tcpconnectorGetLineIdleTable(ts, l), ls->idle_handle, kReadWriteTimeoutMs);
        if (result == kAwqWriteBlocked)
        {
            const bool notify = awqTakePause(&ls->write_queue);
            wioSetCallBackWrite(ls->io, tcpconnectorOnWriteComplete);
            if (notify)
                tunnelPrevDownStreamPause(t, l);
        }
    }
    lineUnref(l);
}
