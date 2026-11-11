#include "structure.h"

#include "loggers/network_logger.h"

static void handleQueueOverflow(tunnel_t *t, line_t *l, tcplistener_tstate_t *ts, tcplistener_lstate_t *ls,
                                size_t incoming_bytes, bool charge_known, size_t incoming_charge)
{
    const buffer_budget_cost_t used = awqGetUsage(&ls->write_queue);
    if (charge_known)
        LOGE("TcpListener: closing connection: write retention admission refused "
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
        LOGE("TcpListener: closing connection: incoming write allocation charge is unrepresentable "
             "(fd=%d, incoming_bytes=%zu)",
             wioGetFD(ls->io),
             incoming_bytes);

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
    const size_t incoming_bytes  = sbufGetLength(buf);
    size_t       incoming_charge = 0;
    const bool   charge_known    = sbufTryGetQueueCharge(buf, &incoming_charge);
    switch (awqAdmit(&ls->write_queue, lineGetBufferPool(l), &buf))
    {
    case kAwqOverflow:
        handleQueueOverflow(t, l, ts, ls, incoming_bytes, charge_known, incoming_charge);
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
