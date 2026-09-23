#include "structure.h"

static void trojanserverDelayedFallbackPayloadTask(tunnel_t *t, line_t *l);

static size_t trojanserverFallbackPendingCount(const trojanserver_lstate_t *ls)
{
    return ls->fallback_pending_up != NULL ? bufferqueueGetBufCount(ls->fallback_pending_up) : 0;
}

static buffer_queue_t *trojanserverEnsureFallbackPendingQueue(trojanserver_lstate_t *ls)
{
    if (ls->fallback_pending_up == NULL)
    {
        ls->fallback_pending_up = memoryAllocate(sizeof(*ls->fallback_pending_up));
        if (UNLIKELY(ls->fallback_pending_up == NULL))
        {
            return NULL;
        }
        *ls->fallback_pending_up = bufferqueueCreate(kTrojanServerBufferQueueCap);
        const bool attached      = bufferqueueTryAttachBudget(ls->fallback_pending_up, &ls->output_budget);
        assert(attached);
        discard attached;
    }

    return ls->fallback_pending_up;
}

static void trojanserverRecycleFallbackPendingQueue(buffer_queue_t *pending, buffer_pool_t *pool)
{
    while (bufferqueueGetBufCount(pending) > 0)
    {
        bufferpoolReuseBuffer(pool, bufferqueuePopFront(pending));
    }

    bufferqueueDestroy(pending);
    memoryFree(pending);
}

static void trojanserverDiscardFallbackPendingPayload(trojanserver_lstate_t *ls, buffer_pool_t *pool)
{
    buffer_queue_t *pending = ls->fallback_pending_up;
    ls->fallback_pending_up = NULL;
    if (pending != NULL)
    {
        trojanserverRecycleFallbackPendingQueue(pending, pool);
    }
}

static sbuf_t *trojanserverMergeQueue(buffer_queue_t *queue, buffer_pool_t *pool)
{
    uint32_t total   = (uint32_t) bufferqueueGetBufLen(queue);
    uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    if (bufferqueueGetBufCount(queue) == 0)
        return NULL;
    if (bufferqueueGetBufCount(queue) == 1 && sbufGetLeftCapacity(bufferqueueFront(queue)) >= padding)
        return bufferqueuePopFront(queue);
    bool has_pipe = false;
    c_foreach(i, ww_sbuffer_queue_t, queue->q) has_pipe |= sbufIsSplice(*i.ref);
    sbuf_t *result = has_pipe ? bufferpoolGetSpliceBuffer(pool) : NULL;
    if (result != NULL && sbufGetLeftCapacity(result) < padding)
    {
        bufferpoolReuseBuffer(pool, result);
        result = NULL;
    }
    if (result == NULL)
        result = bufferpoolGetBestFit(pool, total, padding);
    while (bufferqueueGetBufCount(queue) != 0)
    {
        sbuf_t *part = bufferqueuePopFront(queue);
        result       = sbufMoveRangeTo(pool, part, result, sbufGetLength(part), total, padding);
        bufferpoolReuseBuffer(pool, part);
    }
    return result;
}

static sbuf_t *trojanserverDetachFallbackPendingPayload(trojanserver_lstate_t *ls, buffer_pool_t *pool)
{
    buffer_queue_t *pending = ls->fallback_pending_up;
    ls->fallback_pending_up = NULL;
    if (pending == NULL)
        return NULL;
    assert(bufferqueueGetBufLen(pending) <= kTrojanServerMaxPendingBytes);
    sbuf_t *batch = trojanserverMergeQueue(pending, pool);
    bufferqueueDestroy(pending);
    memoryFree(pending);
    return batch;
}

bool trojanserverScheduleFallbackPayloadDrain(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    if (ls->branch != kTrojanServerBranchFallback || ls->fallback_close_draining || ls->branch_initializing ||
        trojanserverFallbackPendingCount(ls) == 0 || ls->fallback_delay_scheduled)
    {
        return true;
    }

    trojanserver_tstate_t *ts = tunnelGetState(t);
    if (ts->fallback_intentional_delay_ms == 0 || ls->next_paused)
        return true;
    uint32_t delay_ms = fastRandJittered32(ts->fallback_intentional_delay_ms, ts->fallback_intentional_delay_jitter_ms);

    ls->fallback_delay_scheduled = true;
    const line_task_submit_result_e result =
        lineScheduleDelayedTask(l, trojanserverDelayedFallbackPayloadTask, delay_ms, t, NULL);
    if (UNLIKELY(result == kLineTaskSubmitRejectedSettled))
    {
        ls->fallback_delay_scheduled = false;
        return false;
    }
    assert((delay_ms == 0 && result == kLineTaskSubmitAcceptedAsync) ||
           (delay_ms > 0 && result == kLineTaskSubmitTimerArmed));
    return true;
}

static void trojanserverDelayedFallbackPayloadTask(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    /* Scheduled line tasks run only while the line is logically alive. */
    assert(ls->phase != kTrojanServerPhaseClosing);
    ls->fallback_delay_scheduled = false;
    if (ls->branch != kTrojanServerBranchFallback || ls->next_paused || ls->pumping || ls->branch_initializing)
        return;
    sbuf_t *buf = trojanserverDetachFallbackPendingPayload(ls, lineGetBufferPool(l));
    if (buf == NULL)
        return;
    lineRef(l);
    ls->pumping = true;
    tunnelUpStreamPayload(trojanserverSelectedUpstream(t, ls), l, buf);
    if (lineIsAlive(l))
    {
        ls->pumping = false;
        trojanserverPump(t, l);
    }
    lineUnref(l);
}

bool trojanserverSendFallbackPayload(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, sbuf_t *buf)
{
    tunnel_t *fallback = trojanserverSelectedUpstream(t, ls);
    assert(ls->branch == kTrojanServerBranchFallback && fallback != NULL);
    trojanserver_tstate_t *ts = tunnelGetState(t);
    if (ts->fallback_intentional_delay_ms == 0 && ! ls->pumping && ! ls->branch_initializing &&
        trojanserverFallbackPendingCount(ls) == 0 && ! ls->fallback_delay_scheduled)
    {
        lineRef(l);
        ls->pumping = true;
        tunnelUpStreamPayload(fallback, l, buf);
        bool alive = lineIsAlive(l);
        if (alive)
        {
            ls->pumping = false;
            trojanserverPump(t, l);
            alive = lineIsAlive(l);
        }
        lineUnref(l);
        return alive;
    }
    buffer_queue_t *pending = trojanserverEnsureFallbackPendingQueue(ls);
    if (UNLIKELY(pending == NULL || ! trojanserverQueuePayload(pending, &buf)))
    {
        lineReuseBuffer(l, buf);
        trojanserverCloseLineBidirectional(t, l);
        return false;
    }
    if (! ls->pumping)
    {
        lineRef(l);
        trojanserverPump(t, l);
        bool alive = lineIsAlive(l);
        lineUnref(l);
        return alive;
    }
    return true;
}

void trojanserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, tunnel_t *fallback)
{
    /* The previous owner may destroy this borrowed line on return, so publish the
     * close gate before the final re-entrant fallback Payload. */
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = NULL;

    lineRef(l);
    ls->phase                                 = kTrojanServerPhaseClosing;
    ls->fallback_close_draining               = true;
    ls->fallback_branch_finished_during_drain = false;

    if (ls->next_paused || ls->branch_initializing)
    {
        trojanserverDiscardFallbackPendingPayload(ls, pool);
    }
    else
    {
        buf = trojanserverDetachFallbackPendingPayload(ls, pool);
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
    trojanserverCloseUdpRemoteLines(t, ls);
    trojanserverLinestateDestroy(ls);

    if (! branch_finished)
    {
        tunnelUpStreamFin(fallback, l);
    }
    lineUnref(l);
}

void trojanserverStartFallback(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);
    if (ts->fallback_tunnel == NULL || ls->input_bytes > kTrojanServerMaxPendingBytes ||
        ! trojanserverRetainActiveHead(ls))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    if (ls->header_filled != 0)
    {
        buffer_pool_t *pool   = lineGetBufferPool(l);
        sbuf_t        *prefix = bufferpoolGetBestFit(pool, ls->header_filled, bufferpoolGetLargeBufferPadding(pool));
        sbufWrite(prefix, ls->header, ls->header_filled);
        sbufSetLength(prefix, ls->header_filled);
        if (UNLIKELY(! bufferqueueTryPushFront(&ls->pending_up, &prefix)))
        {
            bufferpoolReuseBuffer(pool, prefix);
            trojanserverCloseLineBidirectional(t, l);
            return;
        }
    }
    buffer_queue_t *queue = trojanserverEnsureFallbackPendingQueue(ls);
    if (UNLIKELY(queue == NULL))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    bufferqueueDestroy(queue);
    *queue = ls->pending_up;
    bufferqueueInitEmpty(&ls->pending_up);
    if (UNLIKELY(! bufferqueueTryAttachBudget(queue, &ls->output_budget)))
    {
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
    ls->input_bytes = 0;
    trojanserverResetHeader(ls);
    ls->phase               = kTrojanServerPhaseFallback;
    ls->branch              = kTrojanServerBranchFallback;
    ls->next_initialized    = true;
    ls->branch_initializing = true;
    tunnelUpStreamInit(ts->fallback_tunnel, l);
    if (! lineIsAlive(l))
        return;
    ls->branch_initializing = false;
    if (ts->fallback_intentional_delay_ms == 0)
    {
        sbuf_t *batch = trojanserverDetachFallbackPendingPayload(ls, lineGetBufferPool(l));
        if (batch != NULL)
            tunnelUpStreamPayload(ts->fallback_tunnel, l, batch);
    }
}
