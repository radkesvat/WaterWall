#include "auth.h"
#include "internal.h"
#include "loggers/network_logger.h"

static size_t vmessserverFallbackPendingCount(const vmessserver_lstate_t *ls)
{
    return ls->fallback_pending_up != NULL ? bufferqueueGetBufCount(ls->fallback_pending_up) : 0;
}

static buffer_queue_t *vmessserverEnsureFallbackPendingQueue(vmessserver_lstate_t *ls)
{
    if (ls->fallback_pending_up == NULL)
    {
        ls->fallback_pending_up  = memoryAllocate(sizeof(*ls->fallback_pending_up));
        *ls->fallback_pending_up = bufferqueueCreate(kVmessServerBufferQueueCap);
        bool attached            = bufferqueueTryAttachBudget(ls->fallback_pending_up, &ls->upstream_budget);
        assert(attached);
        discard attached;
    }

    return ls->fallback_pending_up;
}

static void vmessserverRecycleFallbackPendingQueue(buffer_queue_t *pending, buffer_pool_t *pool)
{
    while (bufferqueueGetBufCount(pending) > 0)
    {
        bufferpoolReuseBuffer(pool, bufferqueuePopFront(pending));
    }

    bufferqueueDestroy(pending);
    memoryFree(pending);
}

static void vmessserverDiscardFallbackPendingPayload(vmessserver_lstate_t *ls, buffer_pool_t *pool)
{
    buffer_queue_t *pending = ls->fallback_pending_up;
    ls->fallback_pending_up = NULL;
    if (pending != NULL)
    {
        vmessserverRecycleFallbackPendingQueue(pending, pool);
    }
}

static bool vmessserverDetachFallbackPendingPayload(vmessserver_lstate_t *ls, buffer_pool_t *pool, sbuf_t **out)
{
    *out = NULL;

    buffer_queue_t *pending = ls->fallback_pending_up;
    ls->fallback_pending_up = NULL;
    if (pending == NULL)
    {
        return true;
    }

    const size_t total = bufferqueueGetBufLen(pending);
    if (UNLIKELY(total > kVmessServerMaxPendingBytes || total > UINT32_MAX))
    {
        LOGE("VmessServer: invalid fallback payload batch size=%zu", total);
        vmessserverRecycleFallbackPendingQueue(pending, pool);
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

static void vmessserverDelayedFallbackPayloadTask(tunnel_t *t, line_t *l);

bool vmessserverScheduleFallbackPayloadDrain(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls)
{
    if (ls->phase != kVmessServerPhaseFallback || ls->fallback_close_draining || ls->branch_initializing ||
        ls->input_dispatching || vmessserverFallbackPendingCount(ls) == 0 || ls->fallback_delay_scheduled)
    {
        return true;
    }

    vmessserver_tstate_t *ts = tunnelGetState(t);
    uint32_t              delay_ms =
        ts->fallback_intentional_delay_ms == 0
                         ? 0
                         : fastRandJittered32(ts->fallback_intentional_delay_ms, ts->fallback_intentional_delay_jitter_ms);

    ls->fallback_delay_scheduled = true;
    const line_task_submit_result_e result =
        lineScheduleDelayedTask(l, vmessserverDelayedFallbackPayloadTask, delay_ms, t, NULL);
    if (UNLIKELY(result == kLineTaskSubmitRejectedSettled))
    {
        ls->fallback_delay_scheduled = false;
        return false;
    }
    assert((delay_ms == 0 && result == kLineTaskSubmitAcceptedAsync) ||
           (delay_ms > 0 && result == kLineTaskSubmitTimerArmed));
    return true;
}

static void vmessserverDelayedFallbackPayloadTask(tunnel_t *t, line_t *l)
{
    vmessserver_tstate_t *ts = tunnelGetState(t);
    vmessserver_lstate_t *ls = lineGetState(l, t);

    ls->fallback_delay_scheduled = false;

    if (ls->phase != kVmessServerPhaseFallback || ls->fallback_close_draining || ls->branch_initializing ||
        ls->input_dispatching)
    {
        return;
    }

    buffer_pool_t *pool     = lineGetBufferPool(l);
    tunnel_t      *fallback = ts->fallback_tunnel;
    sbuf_t        *buf      = NULL;
    if (UNLIKELY(! vmessserverDetachFallbackPendingPayload(ls, pool, &buf)))
    {
        vmessserverCloseLineBidirectional(t, l);
        return;
    }

    if (buf == NULL)
    {
        return;
    }
    assert(fallback != NULL);

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
    if (ls->phase != kVmessServerPhaseFallback || ls->fallback_close_draining || ls->branch_initializing)
    {
        return;
    }
    if (UNLIKELY(! vmessserverScheduleFallbackPayloadDrain(t, l, ls)))
    {
        vmessserverCloseLineBidirectional(t, l);
    }
}

bool vmessserverSendFallbackPayload(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, sbuf_t *buf)
{
    vmessserver_tstate_t *ts       = tunnelGetState(t);
    tunnel_t             *fallback = ts->fallback_tunnel;

    if (ls->phase != kVmessServerPhaseFallback || ls->fallback_close_draining)
    {
        lineReuseBuffer(l, buf);
        return false;
    }
    assert(fallback != NULL);

    if (ts->fallback_intentional_delay_ms == 0 && ! ls->input_dispatching && ! ls->branch_initializing &&
        vmessserverFallbackPendingCount(ls) == 0 && ! ls->fallback_delay_scheduled)
    {
        ls->input_dispatching = true;
        if (! lineCallWithRefWithBuf(l, tunnelUpStreamPayload, fallback, buf))
            return false;
        ls = lineGetState(l, t);
        if (ls->tunnel != t)
            return false;
        ls->input_dispatching = false;
        if (! vmessserverScheduleFallbackPayloadDrain(t, l, ls))
        {
            vmessserverCloseLineBidirectional(t, l);
            return false;
        }
        return true;
    }

    buffer_queue_t *pending = vmessserverEnsureFallbackPendingQueue(ls);

    if (! bufferqueueTryPushBack(pending, &buf))
    {
        lineReuseBuffer(l, buf);
        vmessserverCloseLineBidirectional(t, l);
        return false;
    }

    if (UNLIKELY(! vmessserverScheduleFallbackPayloadDrain(t, l, ls)))
    {
        vmessserverCloseLineBidirectional(t, l);
        return false;
    }

    return true;
}

bool vmessserverStartFallback(tunnel_t *t, line_t *l)
{
    vmessserver_tstate_t *ts = tunnelGetState(t);
    vmessserver_lstate_t *ls = lineGetState(l, t);
    if (ts->fallback_tunnel == NULL || ls->auth_recognized)
        goto failed;
    vmessserverAuthLineDetach(ls);
    vmessserverRetainActiveHead(ls);
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
    buffer_queue_t *queue = vmessserverEnsureFallbackPendingQueue(ls);
    bufferqueueDestroy(queue);
    *queue = ls->pending_up;
    bufferqueueInitEmpty(&ls->pending_up);
    if (queue->budget == NULL && ! bufferqueueTryAttachBudget(queue, &ls->upstream_budget))
        goto failed;
    ls->input_bytes         = 0;
    ls->header_filled       = 0;
    ls->phase               = kVmessServerPhaseFallback;
    ls->branch_initializing = true;
    lineMarkFallback(l);
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
        if (! vmessserverDetachFallbackPendingPayload(ls, lineGetBufferPool(l), &batch))
            goto failed;
        if (batch != NULL && ! lineCallWithRefWithBuf(l, tunnelUpStreamPayload, ts->fallback_tunnel, batch))
            return false;
    }
    return true;
failed:
    vmessserverCloseLineBidirectional(t, l);
    return false;
}

void vmessserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, tunnel_t *fallback)
{
    discard t;
    /* The previous owner may destroy this borrowed line on return, so publish the
     * close gate before the final re-entrant fallback Payload. */
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = NULL;

    lineRef(l);
    ls->phase                                 = kVmessServerPhaseClosing;
    ls->fallback_close_draining               = true;
    ls->fallback_branch_finished_during_drain = false;

    if (ls->branch_initializing)
    {
        vmessserverDiscardFallbackPendingPayload(ls, pool);
    }
    else if (! vmessserverDetachFallbackPendingPayload(ls, pool, &buf))
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
    vmessserverLinestateDestroy(ls);

    if (! branch_finished)
    {
        tunnelUpStreamFin(fallback, l);
    }
    lineUnref(l);
}
