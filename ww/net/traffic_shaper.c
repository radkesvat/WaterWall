#include "traffic_shaper.h"

#include "splice_buffer.h"

/* Cancellation owns only this independently synchronized token. It never
 * inspects line state, worker pools, or the provider. The owner detaches its
 * pointer before Finish/quiescence can reclaim embedded state. */
struct traffic_shaper_continuation_s
{
    atomic_uint       references;
    traffic_shaper_t *shaper;
};

static bool trafficshaperCostEmpty(buffer_budget_cost_t cost)
{
    return cost.bytes == 0 && cost.charge == 0 && cost.entries == 0;
}

static buffer_budget_cost_t trafficshaperCost(const traffic_shaper_t *shaper, const sbuf_t *buffer)
{
    return (buffer_budget_cost_t) {sbufGetLength(buffer),
                                   shaper->allocation_charge ? sbufGetAllocationCharge(buffer)
                                                             : sbufGetQueueCharge(buffer),
                                   1};
}

static bool trafficshaperReserve(traffic_shaper_t *shaper, buffer_budget_cost_t cost)
{
    if (! bufferbudgetTryAcquire(shaper->budget, cost))
        return false;
    if (shaper->ops->reserve != NULL && ! shaper->ops->reserve(shaper->context, cost))
    {
        bufferbudgetRelease(shaper->budget, cost);
        return false;
    }
    shaper->retained_cost.bytes += cost.bytes;
    shaper->retained_cost.charge += cost.charge;
    shaper->retained_cost.entries += cost.entries;
    return true;
}

static void trafficshaperRelease(traffic_shaper_t *shaper, buffer_budget_cost_t cost)
{
    assert(shaper->retained_cost.bytes >= cost.bytes && shaper->retained_cost.charge >= cost.charge &&
           shaper->retained_cost.entries >= cost.entries);
    shaper->retained_cost.bytes -= cost.bytes;
    shaper->retained_cost.charge -= cost.charge;
    shaper->retained_cost.entries -= cost.entries;
    bufferbudgetRelease(shaper->budget, cost);
    if (shaper->ops->release != NULL && ! trafficshaperCostEmpty(cost))
        shaper->ops->release(shaper->context, cost);
}

size_t trafficshaperPending(const traffic_shaper_t *shaper)
{
    return (size_t) ww_sbuffer_queue_t_size(&shaper->queue.q) + (shaper->candidate != NULL);
}

static void trafficshaperNotify(traffic_shaper_t *shaper)
{
    if (shaper->ops->state_changed != NULL)
        shaper->ops->state_changed(
            shaper->context, trafficshaperPending(shaper) != 0, shaper->externally_paused || shaper->stopped);
}

static void trafficshaperContinuationUnref(traffic_shaper_continuation_t *continuation)
{
    if (atomic_fetch_sub_explicit(&continuation->references, 1, memory_order_acq_rel) == 1)
        memoryFree(continuation);
}

static void trafficshaperDetachContinuation(traffic_shaper_t *shaper)
{
    traffic_shaper_continuation_t *continuation = shaper->continuation;
    if (continuation != NULL)
    {
        shaper->continuation = NULL;
        continuation->shaper = NULL;
        trafficshaperContinuationUnref(continuation);
    }
}

static void trafficshaperContinuationCancel(tunnel_t *token, line_t *line, line_task_cancel_reason_e reason)
{
    discard line;
    discard reason;
    trafficshaperContinuationUnref((traffic_shaper_continuation_t *) token);
}

static void trafficshaperContinuationRun(tunnel_t *token, line_t *line)
{
    discard                        line;
    traffic_shaper_continuation_t *continuation = (traffic_shaper_continuation_t *) token;
    traffic_shaper_t              *shaper       = continuation->shaper;
    if (shaper != NULL)
    {
        assert(shaper->continuation == continuation);
        trafficshaperDetachContinuation(shaper);
        trafficshaperDrain(shaper);
    }
    trafficshaperContinuationUnref(continuation);
}

void trafficshaperTimerCallback(wtimer_t *timer)
{
    traffic_shaper_t *shaper = weventGetUserdata(timer);
    assert(shaper != NULL && shaper->timer == timer && lineIsAlive(shaper->line));
    shaper->timer = NULL;
    trafficshaperDrain(shaper);
}

bool trafficshaperSchedule(traffic_shaper_t *shaper, uint32_t delay_ms)
{
    if (shaper->stopped)
        return false;
    if (delay_ms != 0)
    {
        /* One queued continuation already guarantees the next owner turn.
         * Let it recompute a wait instead of accumulating detached no-op tasks
         * while new input or configuration changes the required delay. */
        if (shaper->continuation != NULL)
            return true;
        if (shaper->timer != NULL)
            return wtimerReset(shaper->timer, delay_ms);
        wtimer_t *timer = wtimerAdd(getWorkerLoop(lineGetWID(shaper->line)), trafficshaperTimerCallback, delay_ms, 1);
        if (timer == NULL)
            return false;
        shaper->timer = timer;
        weventSetUserData(timer, shaper);
        return true;
    }
    if (shaper->continuation != NULL)
        return true;
    if (shaper->timer != NULL)
    {
        weventSetUserData(shaper->timer, NULL);
        wtimerDelete(shaper->timer);
        shaper->timer = NULL;
    }
    traffic_shaper_continuation_t *continuation = memoryAllocate(sizeof(*continuation));
    atomic_init(&continuation->references, 2);
    continuation->shaper                   = shaper;
    shaper->continuation                   = continuation;
    const line_task_submit_result_e result = lineScheduleTask(
        shaper->line, trafficshaperContinuationRun, (tunnel_t *) continuation, trafficshaperContinuationCancel);
    if (result == kLineTaskSubmitRejectedSettled)
    {
        /* Synchronous cancellation released only its token reference. */
        trafficshaperDetachContinuation(shaper);
        return false;
    }
    return true;
}

void trafficshaperInit(traffic_shaper_t *shaper, line_t *line, buffer_budget_t *budget, const traffic_shaper_ops_t *ops,
                       void *context, traffic_shaper_mode_t mode, uint32_t yield_ms, bool allocation_charge)
{
    assert(line != NULL && budget != NULL && ops != NULL && ops->preview != NULL && ops->commit != NULL &&
           ops->forward != NULL && ops->pressure != NULL && ops->close != NULL);
    *shaper = (traffic_shaper_t) {.budget            = budget,
                                  .ops               = ops,
                                  .context           = context,
                                  .line              = line,
                                  .yield_ms          = yield_ms,
                                  .mode              = mode,
                                  .allocation_charge = allocation_charge};
    bufferqueueInitEmpty(&shaper->queue);
}

void trafficshaperQuiesce(traffic_shaper_t *shaper)
{
    shaper->stopped = true;
    if (shaper->timer != NULL)
    {
        weventSetUserData(shaper->timer, NULL);
        wtimerDelete(shaper->timer);
        shaper->timer = NULL;
    }
    trafficshaperDetachContinuation(shaper);
    trafficshaperNotify(shaper);
}

void trafficshaperDestroy(traffic_shaper_t *shaper)
{
    trafficshaperQuiesce(shaper);
    if (shaper->candidate != NULL)
    {
        lineReuseBuffer(shaper->line, shaper->candidate);
        shaper->candidate = NULL;
    }
    bufferqueueDestroy(&shaper->queue);
    trafficshaperRelease(shaper, shaper->retained_cost);
    trafficshaperNotify(shaper);
}

static void trafficshaperForward(traffic_shaper_t *shaper, sbuf_t *buffer, bool close_after)
{
    const traffic_shaper_ops_t *ops     = shaper->ops;
    void                       *context = shaper->context;
    line_t                     *line    = shaper->line;
    if (! close_after)
    {
        ops->forward(context, buffer);
        return;
    }
    lineRef(line);
    ops->forward(context, buffer);
    if (lineIsAlive(line))
        ops->close(context);
    lineUnref(line);
}

static void trafficshaperClose(traffic_shaper_t *shaper)
{
    shaper->ops->close(shaper->context);
}

static bool trafficshaperSchedulePreview(traffic_shaper_t *shaper, traffic_shaper_preview_t preview)
{
    return trafficshaperSchedule(shaper, preview.retry_ms != 0 ? preview.retry_ms : shaper->yield_ms);
}

traffic_shaper_submit_t trafficshaperSubmit(traffic_shaper_t *shaper, sbuf_t *buffer)
{
    if (shaper->stopped)
        return kTrafficShaperRefused;
    const size_t length = sbufGetLength(buffer);
    if (! shaper->externally_paused && trafficshaperPending(shaper) == 0)
    {
        traffic_shaper_preview_t preview = shaper->ops->preview(shaper->context, length, false);
        if (preview.reject)
        {
            lineReuseBuffer(shaper->line, buffer);
            trafficshaperClose(shaper);
            return kTrafficShaperConsumed;
        }
        if (preview.bytes >= length && preview.retry_ms == 0)
        {
            traffic_shaper_commit_t result = shaper->ops->commit(shaper->context, length, false, false);
            if (result == kTrafficShaperForward || result == kTrafficShaperForwardClose)
            {
                trafficshaperForward(shaper, buffer, result == kTrafficShaperForwardClose);
                return kTrafficShaperConsumed;
            }
            if (result == kTrafficShaperReject)
            {
                lineReuseBuffer(shaper->line, buffer);
                trafficshaperClose(shaper);
                return kTrafficShaperConsumed;
            }
        }
    }

    buffer_budget_cost_t cost = trafficshaperCost(shaper, buffer);
    if (! trafficshaperReserve(shaper, cost))
    {
        trafficshaperNotify(shaper);
        return kTrafficShaperRefused;
    }
    if (! bufferqueueTryPushBack(&shaper->queue, &buffer))
    {
        trafficshaperRelease(shaper, cost);
        trafficshaperNotify(shaper);
        return kTrafficShaperRefused;
    }
    trafficshaperNotify(shaper);
    if (! shaper->externally_paused)
    {
        traffic_shaper_preview_t preview = shaper->ops->preview(
            shaper->context,
            sbufGetLength(shaper->candidate != NULL ? shaper->candidate : bufferqueueFront(&shaper->queue)),
            true);
        if (preview.reject || ! trafficshaperSchedulePreview(shaper, preview))
        {
            trafficshaperClose(shaper);
            return kTrafficShaperConsumed;
        }
    }
    /* UDP adapters drop incoming packets while paused. A datagram backlog
     * therefore relies on bounded admission, not a producer hold that would
     * discard packets before this queue fills. External pressure still applies. */
    if (shaper->mode == kTrafficShaperStream && ! shaper->locally_paused)
    {
        shaper->locally_paused = true;
        if (! shaper->externally_paused)
            shaper->ops->pressure(shaper->context, true);
    }
    return kTrafficShaperRetained;
}

/* Move a FIFO prefix to a retained candidate. Reserve its worst-case ordinary
 * fallback plus splice wrapper before consuming any source bytes. Logical bytes
 * transfer between owners and are never counted twice. */
static bool trafficshaperPrepare(traffic_shaper_t *shaper, size_t bytes)
{
    assert(shaper->candidate == NULL);
    sbuf_t *source = (sbuf_t *) bufferqueueFront(&shaper->queue);
    assert(source != NULL && bytes <= sbufGetLength(source));
    if (bytes == sbufGetLength(source))
    {
        shaper->candidate = bufferqueuePopFront(&shaper->queue);
        return true;
    }
    assert(shaper->mode == kTrafficShaperStream && bytes != 0);
    if (! bufferqueueReserveExtra(&shaper->queue, 1))
        return false;
    buffer_pool_t    *pool    = lineGetBufferPool(shaper->line);
    uint16_t          padding = bufferpoolGetLargeBufferPadding(pool);
    buffer_pool_fit_t fit;
    if (! bufferpoolQueryBestFit(pool, bytes, padding, &fit))
        return false;
    sbuf_t              *destination = NULL;
    buffer_budget_cost_t extra       = {0, fit.allocation_charge, 1};
    if (! trafficshaperReserve(shaper, extra))
        return false;
    if (sbufIsSplice(source))
    {
        // A checked-out empty wrapper already belongs to this retained turn.
        // Reserve its fixed geometry before checkout, alongside the ordinary
        // fallback allowance. Refused wrapper credit can use that fallback.
        const buffer_budget_cost_t wrapper = {0,
                                              sizeof(sbuf_t) + (size_t) bufferpoolGetSpliceBufferPadding(pool) +
                                                  bufferpoolGetSpliceBufferStorageSize(pool) + kSbufAllocationAlignment,
                                              1};
        if (trafficshaperReserve(shaper, wrapper))
        {
            destination = bufferpoolGetSpliceBuffer(pool);
            if (destination == NULL)
                trafficshaperRelease(shaper, wrapper);
            else
            {
                assert(trafficshaperCost(shaper, destination).charge == wrapper.charge);
                extra.charge += wrapper.charge;
                extra.entries += wrapper.entries;
            }
        }
    }
    if (destination == NULL)
        destination = bufferpoolGetBestFit(pool, (uint32_t) bytes, padding);
    buffer_budget_cost_t before = trafficshaperCost(shaper, source);
    source                      = bufferqueuePopFront(&shaper->queue);
    shaper->candidate = sbufMoveRangeTo(pool, source, destination, (uint32_t) bytes, (uint32_t) bytes, padding);
    buffer_budget_cost_t after  = trafficshaperCost(shaper, source);
    buffer_budget_cost_t output = trafficshaperCost(shaper, shaper->candidate);
    assert(after.bytes + output.bytes == before.bytes && after.charge <= before.charge);
    assert(output.charge <= extra.charge);
    bufferqueuePushFront(&shaper->queue, source);
    trafficshaperRelease(
        shaper,
        (buffer_budget_cost_t) {0, extra.charge - output.charge + before.charge - after.charge, extra.entries - 1});
    return true;
}

void trafficshaperDrain(traffic_shaper_t *shaper)
{
    if (shaper->stopped)
        return;
    if (trafficshaperPending(shaper) == 0)
    {
        trafficshaperNotify(shaper);
        if (shaper->locally_paused)
        {
            shaper->locally_paused = false;
            if (! shaper->externally_paused)
                shaper->ops->pressure(shaper->context, false);
        }
        return;
    }
    if (shaper->externally_paused)
        return;

    sbuf_t *head   = shaper->candidate != NULL ? shaper->candidate : (sbuf_t *) bufferqueueFront(&shaper->queue);
    size_t  length = sbufGetLength(head);
    traffic_shaper_preview_t preview = shaper->ops->preview(shaper->context, length, true);
    if (preview.reject)
    {
        trafficshaperClose(shaper);
        return;
    }
    size_t bytes = min(preview.bytes, length);
    if ((bytes == 0 && length != 0) || preview.retry_ms != 0 ||
        (shaper->mode == kTrafficShaperDatagram && bytes != length))
    {
        if (! trafficshaperSchedule(shaper, preview.retry_ms != 0 ? preview.retry_ms : 1))
            trafficshaperClose(shaper);
        return;
    }
    if (shaper->candidate == NULL && ! trafficshaperPrepare(shaper, bytes))
    {
        trafficshaperClose(shaper);
        return;
    }
    if (bytes != sbufGetLength(shaper->candidate))
    {
        assert(shaper->mode == kTrafficShaperStream && bytes != 0);
        if (! bufferqueueReserveExtra(&shaper->queue, 1))
        {
            trafficshaperClose(shaper);
            return;
        }
        sbuf_t *prepared  = shaper->candidate;
        shaper->candidate = NULL;
        bufferqueuePushFront(&shaper->queue, prepared);
        if (! trafficshaperPrepare(shaper, bytes))
        {
            trafficshaperClose(shaper);
            return;
        }
    }
    bool remaining = bufferqueueGetBufCount(&shaper->queue) != 0;
    /* Establish the next asynchronous obligation before a charge-at-handoff
     * commit. Its callback cannot execute within this owner-worker callback. */
    if ((remaining || shaper->locally_paused) && ! trafficshaperSchedule(shaper, shaper->yield_ms))
    {
        trafficshaperClose(shaper);
        return;
    }
    traffic_shaper_commit_t result = shaper->ops->commit(shaper->context, bytes, true, remaining);
    if (result == kTrafficShaperWait)
    {
        preview = shaper->ops->preview(shaper->context, bytes, true);
        if (preview.reject || ! trafficshaperSchedule(shaper, preview.retry_ms != 0 ? preview.retry_ms : 1))
            trafficshaperClose(shaper);
        return;
    }
    if (result == kTrafficShaperReject)
    {
        trafficshaperClose(shaper);
        return;
    }
    sbuf_t              *output = shaper->candidate;
    buffer_budget_cost_t cost   = trafficshaperCost(shaper, output);
    shaper->candidate           = NULL;
    trafficshaperRelease(shaper, cost);
    /* A datagram direction has no local-pressure release tick. Publish its
     * empty FIFO now, after releasing costs and before reentrant delivery. */
    trafficshaperNotify(shaper);
    /* Provider commit has already rotated/removed any shared waiter ticket.
     * No fallible operation may intervene between this commit and handoff. */
    trafficshaperForward(shaper, output, result == kTrafficShaperForwardClose);
}

void trafficshaperSetExternalPause(traffic_shaper_t *shaper, bool paused)
{
    bool was_paused           = shaper->externally_paused;
    bool held                 = shaper->externally_paused || shaper->locally_paused;
    shaper->externally_paused = paused;
    trafficshaperNotify(shaper);
    if (paused)
    {
        if (! held)
            shaper->ops->pressure(shaper->context, true);
        return;
    }
    if (trafficshaperPending(shaper) != 0 || shaper->locally_paused)
    {
        if (! trafficshaperSchedule(shaper, shaper->yield_ms))
        {
            trafficshaperClose(shaper);
            return;
        }
    }
    if (was_paused && ! shaper->locally_paused)
        shaper->ops->pressure(shaper->context, false);
}
