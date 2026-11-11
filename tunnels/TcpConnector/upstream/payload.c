#include "structure.h"

#include "loggers/network_logger.h"

static void handleQueueOverflow(tunnel_t *t, line_t *l, tcpconnector_tstate_t *ts, tcpconnector_lstate_t *ls,
                                size_t incoming_bytes, bool charge_known, size_t incoming_charge)
{
    const buffer_budget_cost_t used = awqGetUsage(&ls->write_queue);
    if (charge_known)
        LOGE("TcpConnector: closing connection: write retention admission refused "
             "(fd=%d, retained_bytes=%zu, incoming_bytes=%zu, byte_limit=%u, "
             "retained_charge_bytes=%zu, incoming_charge_bytes=%zu, charge_limit_bytes=%u)",
             wioGetFD(ls->io),
             used.bytes,
             incoming_bytes,
             (unsigned) kAwqMaxRetained,
             used.charge,
             incoming_charge,
             (unsigned) kAwqMaxRetained);
    else
        LOGE("TcpConnector: closing connection: incoming write allocation charge is unrepresentable "
             "(fd=%d, incoming_bytes=%zu)",
             wioGetFD(ls->io),
             incoming_bytes);

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
    const size_t incoming_bytes  = sbufGetLength(buf);
    size_t       incoming_charge = 0;
    const bool   charge_known    = sbufTryGetQueueCharge(buf, &incoming_charge);
    switch (awqAdmit(&ls->write_queue, lineGetBufferPool(l), &buf))
    {
    case kAwqOverflow:
        handleQueueOverflow(t, l, ts, ls, incoming_bytes, charge_known, incoming_charge);
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
