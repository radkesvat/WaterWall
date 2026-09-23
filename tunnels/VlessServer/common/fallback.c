#include "loggers/network_logger.h"
#include "structure.h"

static size_t vlessserverFallbackPendingCount(const vlessserver_lstate_t *ls)
{
    return ls->fallback_pending_up != NULL ? bufferqueueGetBufCount(ls->fallback_pending_up) : 0;
}

static buffer_queue_t *vlessserverEnsureFallbackPendingQueue(vlessserver_lstate_t *ls)
{
    if (ls->fallback_pending_up == NULL)
    {
        ls->fallback_pending_up = memoryAllocate(sizeof(*ls->fallback_pending_up));
        if (UNLIKELY(ls->fallback_pending_up == NULL))
        {
            return NULL;
        }
        *ls->fallback_pending_up = bufferqueueCreate(kVlessServerBufferQueueCap);
        bool attached            = bufferqueueTryAttachBudget(ls->fallback_pending_up, &ls->upstream_budget);
        assert(attached);
        discard attached;
    }

    return ls->fallback_pending_up;
}

static void vlessserverRecycleFallbackPendingQueue(buffer_queue_t *pending, buffer_pool_t *pool)
{
    while (bufferqueueGetBufCount(pending) > 0)
    {
        bufferpoolReuseBuffer(pool, bufferqueuePopFront(pending));
    }

    bufferqueueDestroy(pending);
    memoryFree(pending);
}

static void vlessserverDiscardFallbackPendingPayload(vlessserver_lstate_t *ls, buffer_pool_t *pool)
{
    buffer_queue_t *pending = ls->fallback_pending_up;
    ls->fallback_pending_up = NULL;
    if (pending != NULL)
    {
        vlessserverRecycleFallbackPendingQueue(pending, pool);
    }
}

static bool vlessserverDetachFallbackPendingPayload(vlessserver_lstate_t *ls, buffer_pool_t *pool, sbuf_t **out)
{
    *out = NULL;

    buffer_queue_t *pending = ls->fallback_pending_up;
    ls->fallback_pending_up = NULL;
    if (pending == NULL)
    {
        return true;
    }

    const size_t total = bufferqueueGetBufLen(pending);
    if (UNLIKELY(total > kVlessServerMaxPendingBytes || total > UINT32_MAX))
    {
        LOGE("VlessServer: invalid fallback payload batch size=%zu", total);
        vlessserverRecycleFallbackPendingQueue(pending, pool);
        return false;
    }

    sbuf_t  *merged  = NULL;
    uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    if (bufferqueueGetBufCount(pending) == 1 && sbufGetLeftCapacity(bufferqueueFront(pending)) >= padding)
        merged = bufferqueuePopFront(pending);
    else if (bufferqueueGetBufCount(pending) != 0)
    {
        bool has_pipe = false;
        c_foreach(i, ww_sbuffer_queue_t, pending->q) has_pipe |= sbufIsSplice(*i.ref);
        merged = has_pipe ? bufferpoolGetSpliceBuffer(pool) : NULL;
        if (merged != NULL && sbufGetLeftCapacity(merged) < padding)
        {
            bufferpoolReuseBuffer(pool, merged);
            merged = NULL;
        }
        if (merged == NULL)
            merged = bufferpoolGetBestFit(pool, (uint32_t) total, padding);
        while (bufferqueueGetBufCount(pending) != 0)
        {
            sbuf_t *part = bufferqueuePopFront(pending);
            merged       = sbufMoveRangeTo(pool, part, merged, sbufGetLength(part), (uint32_t) total, padding);
            bufferpoolReuseBuffer(pool, part);
        }
    }

    bufferqueueDestroy(pending);
    memoryFree(pending);
    *out = merged;
    return true;
}

static void vlessserverDelayedFallbackPayloadTask(tunnel_t *t, line_t *l);

bool vlessserverScheduleFallbackPayloadDrain(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    if (ls->phase != kVlessServerPhaseFallback || ls->fallback_close_draining || ls->branch_initializing ||
        ls->input_dispatching || ls->fallback_payload_paused || vlessserverFallbackPendingCount(ls) == 0 ||
        ls->fallback_delay_scheduled)
    {
        return true;
    }

    vlessserver_tstate_t *ts = tunnelGetState(t);
    uint32_t              delay_ms =
        ts->fallback_intentional_delay_ms == 0
                         ? 0
                         : fastRandJittered32(ts->fallback_intentional_delay_ms, ts->fallback_intentional_delay_jitter_ms);

    ls->fallback_delay_scheduled = true;
    const line_task_submit_result_e result =
        lineScheduleDelayedTask(l, vlessserverDelayedFallbackPayloadTask, delay_ms, t, NULL);
    if (UNLIKELY(result == kLineTaskSubmitRejectedSettled))
    {
        ls->fallback_delay_scheduled = false;
        return false;
    }
    assert((delay_ms == 0 && result == kLineTaskSubmitAcceptedAsync) ||
           (delay_ms > 0 && result == kLineTaskSubmitTimerArmed));
    return true;
}

static void vlessserverDelayedFallbackPayloadTask(tunnel_t *t, line_t *l)
{
    vlessserver_tstate_t *ts = tunnelGetState(t);
    vlessserver_lstate_t *ls = lineGetState(l, t);

    ls->fallback_delay_scheduled = false;

    if (ls->phase != kVlessServerPhaseFallback || ls->fallback_close_draining || ls->branch_initializing ||
        ls->input_dispatching || ls->fallback_payload_paused)
    {
        return;
    }

    buffer_pool_t *pool     = lineGetBufferPool(l);
    tunnel_t      *fallback = ts->fallback_tunnel;
    sbuf_t        *buf      = NULL;
    if (UNLIKELY(! vlessserverDetachFallbackPendingPayload(ls, pool, &buf)))
    {
        vlessserverCloseLineBidirectional(t, l);
        return;
    }

    if (buf == NULL)
    {
        return;
    }
    if (UNLIKELY(fallback == NULL))
    {
        bufferpoolReuseBuffer(pool, buf);
        vlessserverCloseLineBidirectional(t, l);
        return;
    }

    ls->input_dispatching = true;
    tunnelUpStreamPayload(fallback, l, buf);
    if (! lineIsAlive(l))
    {
        return;
    }

    ls = lineGetState(l, t);
    if (ls->tunnel != t)
        return;
    ls->input_dispatching = false;
    if (ls->phase != kVlessServerPhaseFallback || ls->fallback_close_draining || ls->branch_initializing ||
        ls->input_dispatching || ls->fallback_payload_paused)
    {
        return;
    }
    if (UNLIKELY(! vlessserverScheduleFallbackPayloadDrain(t, l, ls)))
    {
        vlessserverCloseLineBidirectional(t, l);
    }
}

bool vlessserverSendFallbackPayload(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, sbuf_t *buf)
{
    vlessserver_tstate_t *ts       = tunnelGetState(t);
    tunnel_t             *fallback = ts->fallback_tunnel;

    if (fallback == NULL || ls->phase != kVlessServerPhaseFallback || ls->fallback_close_draining)
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    if (ts->fallback_intentional_delay_ms == 0 && ! ls->input_dispatching && ! ls->branch_initializing &&
        vlessserverFallbackPendingCount(ls) == 0 && ! ls->fallback_delay_scheduled)
    {
        ls->input_dispatching = true;
        if (! lineCallWithRefWithBuf(l, tunnelUpStreamPayload, fallback, buf))
            return false;
        ls = lineGetState(l, t);
        if (ls->tunnel != t)
            return false;
        ls->input_dispatching = false;
        if (! vlessserverScheduleFallbackPayloadDrain(t, l, ls))
        {
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }
        return true;
    }

    buffer_queue_t *pending = vlessserverEnsureFallbackPendingQueue(ls);
    if (UNLIKELY(pending == NULL))
    {
        lineReuseBuffer(l, buf);
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    if (! bufferqueueTryPushBack(pending, &buf))
    {
        lineReuseBuffer(l, buf);
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    if (UNLIKELY(! vlessserverScheduleFallbackPayloadDrain(t, l, ls)))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    return true;
}

bool vlessserverStartFallback(tunnel_t *t, line_t *l)
{
    vlessserver_tstate_t *ts = tunnelGetState(t);
    vlessserver_lstate_t *ls = lineGetState(l, t);
    if (ts->fallback_tunnel == NULL || ! vlessserverRetainActiveHead(ls))
        goto failed;
    if (ls->header_filled != 0)
    {
        buffer_pool_t *pool   = lineGetBufferPool(l);
        sbuf_t        *prefix = bufferpoolGetBestFit(pool, ls->header_filled, bufferpoolGetLargeBufferPadding(pool));
        sbufWrite(prefix, ls->header, ls->header_filled);
        sbufSetLength(prefix, ls->header_filled);
        if (! bufferqueueTryPushFront(&ls->pending_up, &prefix))
        {
            lineReuseBuffer(l, prefix);
            goto failed;
        }
    }
    buffer_queue_t *queue = vlessserverEnsureFallbackPendingQueue(ls);
    if (queue == NULL)
        goto failed;
    bufferqueueDestroy(queue);
    *queue = ls->pending_up;
    bufferqueueInitEmpty(&ls->pending_up);
    if (! bufferqueueTryAttachBudget(queue, &ls->upstream_budget))
        goto failed;
    ls->input_bytes         = 0;
    ls->header_filled       = 0;
    ls->phase               = kVlessServerPhaseFallback;
    ls->branch_initializing = true;
    if (! lineCallWithRef(l, tunnelUpStreamInit, ts->fallback_tunnel))
        return false;
    ls = lineGetState(l, t);
    if (ls->tunnel != t)
        return false;
    ls->branch_initializing = false;
    if (ls->response_paused && ! lineCallWithRef(l, tunnelUpStreamPause, ts->fallback_tunnel))
        return false;
    if (ls->tunnel != t)
        return false;
    if (ts->fallback_intentional_delay_ms == 0)
    {
        sbuf_t *batch = NULL;
        if (! vlessserverDetachFallbackPendingPayload(ls, lineGetBufferPool(l), &batch))
            goto failed;
        if (batch != NULL && ! lineCallWithRefWithBuf(l, tunnelUpStreamPayload, ts->fallback_tunnel, batch))
            return false;
    }
    return true;
failed:
    vlessserverCloseLineBidirectional(t, l);
    return false;
}

void vlessserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, tunnel_t *fallback)
{
    discard t;
    /* The previous owner may destroy this borrowed line on return, so publish the
     * close gate before the final re-entrant fallback Payload. */
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = NULL;

    lineRef(l);
    ls->phase                                 = kVlessServerPhaseClosing;
    ls->fallback_close_draining               = true;
    ls->fallback_branch_finished_during_drain = false;

    if (ls->fallback_payload_paused || ls->branch_initializing)
    {
        vlessserverDiscardFallbackPendingPayload(ls, pool);
    }
    else if (! vlessserverDetachFallbackPendingPayload(ls, pool, &buf))
    {
        buf = NULL;
    }

    if (buf != NULL)
    {
        tunnelUpStreamPayload(fallback, l, buf);
        if (! lineIsAlive(l))
        {
            lineUnref(l);
            return;
        }
    }

    const bool branch_finished = ls->fallback_branch_finished_during_drain;
    vlessserverLinestateDestroy(ls);

    if (! branch_finished)
    {
        tunnelUpStreamFin(fallback, l);
    }
    lineUnref(l);
}
