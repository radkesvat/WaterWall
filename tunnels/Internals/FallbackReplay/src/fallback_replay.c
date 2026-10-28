#include "FallbackReplay/fallback_replay.h"

#include "splice_buffer.h"
#include "wfrand.h"

static bool fallbackReplayBatchFits(fallback_replay_t *replay, buffer_pool_t *pool, size_t additional_bytes)
{
    const size_t pending_bytes = bufferqueueGetBufLen(&replay->pending);
    if (additional_bytes > replay->config->max_batch_bytes ||
        pending_bytes > replay->config->max_batch_bytes - additional_bytes)
        return false;

    const size_t total = pending_bytes + additional_bytes;
    if (total > UINT32_MAX)
        return false;

    buffer_pool_fit_t fit;
    return bufferpoolQueryBestFit(pool, total, bufferpoolGetLargeBufferPadding(pool), &fit);
}

static void fallbackReplayDiscardPending(fallback_replay_t *replay, buffer_pool_t *pool)
{
    while (bufferqueueGetBufCount(&replay->pending) != 0)
        bufferpoolReuseBuffer(pool, bufferqueuePopFront(&replay->pending));
}

/* Admission already proved complete merge geometry against fixed pool/config
 * bounds. Keep the empty queue bound for subsequent reentrant admission. */
static sbuf_t *fallbackReplayTakeBatch(fallback_replay_t *replay, buffer_pool_t *pool)
{
    if (bufferqueueGetBufCount(&replay->pending) == 0)
        return NULL;
    assert(fallbackReplayBatchFits(replay, pool, 0));

    const uint32_t total   = (uint32_t) bufferqueueGetBufLen(&replay->pending);
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    if (bufferqueueGetBufCount(&replay->pending) == 1 &&
        sbufGetLeftCapacity(bufferqueueFront(&replay->pending)) >= padding)
    {
        return bufferqueuePopFront(&replay->pending);
    }

    bool has_splice = false;
    c_foreach(item, ww_sbuffer_queue_t, replay->pending.q) has_splice |= sbufIsSplice(*item.ref);
    sbuf_t *merged = has_splice ? bufferpoolGetSpliceBuffer(pool) : NULL;
    if (merged != NULL && sbufGetLeftCapacity(merged) < padding)
    {
        bufferpoolReuseBuffer(pool, merged);
        merged = NULL;
    }
    if (merged == NULL)
        merged = bufferpoolGetBestFit(pool, total, padding);

    while (bufferqueueGetBufCount(&replay->pending) != 0)
    {
        sbuf_t *part = bufferqueuePopFront(&replay->pending);
        merged       = sbufMoveRangeTo(pool, part, merged, sbufGetLength(part), total, padding);
        bufferpoolReuseBuffer(pool, part);
    }
    return merged;
}

static fallback_replay_result_e fallbackReplaySchedule(fallback_replay_t *replay, tunnel_t *owner, line_t *line,
                                                       LineTaskFnNoBuf task)
{
    if (replay->branch == NULL || replay->closing)
        return kFallbackReplayGone;
    if (replay->startup || replay->dispatching || replay->scheduled || bufferqueueGetBufCount(&replay->pending) == 0)
        return kFallbackReplayOk;
    if (replay->config->delay_ms == 0 && replay->config->zero_delay_mode == kFallbackReplayCallerDriven)
        return kFallbackReplayOk;

    const uint32_t delay_ms =
        replay->config->delay_ms == 0 ? 0 : fastRandJittered32(replay->config->delay_ms, replay->config->jitter_ms);
    replay->scheduled                      = true;
    const line_task_submit_result_e result = lineScheduleDelayedTask(line, task, delay_ms, owner, NULL);
    if (result == kLineTaskSubmitRejectedSettled)
    {
        replay->scheduled = false;
        return kFallbackReplayRefused;
    }
    assert((delay_ms == 0 && result == kLineTaskSubmitAcceptedAsync) ||
           (delay_ms != 0 && result == kLineTaskSubmitTimerArmed));
    return kFallbackReplayOk;
}

static fallback_replay_result_e fallbackReplayDispatch(fallback_replay_t *replay, tunnel_t *owner, line_t *line,
                                                       sbuf_t *payload, LineTaskFnNoBuf task)
{
    const bool was_dispatching = replay->dispatching;
    replay->dispatching        = true;
    if (! lineCallWithRefWithBuf(line, tunnelUpStreamPayload, replay->branch, payload))
        return kFallbackReplayGone;
    if (replay->branch == NULL)
        return kFallbackReplayGone;
    replay->dispatching = was_dispatching;
    return fallbackReplaySchedule(replay, owner, line, task);
}

fallback_replay_result_e fallbackReplayBegin(fallback_replay_t *replay, line_t *line, tunnel_t *branch,
                                             const fallback_replay_config_t *config, buffer_budget_t *budget,
                                             buffer_queue_t *transcript)
{
    assert(lineIsAlive(line) && lineIsOnCurrentWorker(line));
    assert(replay->branch == NULL && replay->config == NULL);
    assert(branch != NULL && config != NULL && budget != NULL && transcript != &replay->pending);
    assert(config->zero_delay_mode >= kFallbackReplayDeferred &&
           config->zero_delay_mode <= kFallbackReplayInlineNested);

    replay->pending = *transcript;
    bufferqueueInitEmpty(transcript);
    replay->config       = config;
    replay->branch       = branch;
    replay->initializing = true;
    replay->startup      = true;

    buffer_pool_t *pool     = lineGetBufferPool(line);
    const bool     attached = replay->pending.budget == NULL ? bufferqueueTryAttachBudget(&replay->pending, budget)
                                                             : bufferqueueTryRebindBudget(&replay->pending, budget);
    if (! attached || ! fallbackReplayBatchFits(replay, pool, 0))
    {
        fallbackReplayDestroy(replay, pool);
        return kFallbackReplayRefused;
    }
    return kFallbackReplayOk;
}

void fallbackReplayMarkInitialized(fallback_replay_t *replay)
{
    assert(replay->branch != NULL && replay->initializing && replay->startup && ! replay->closing);
    replay->initializing = false;
}

fallback_replay_result_e fallbackReplayInitDone(fallback_replay_t *replay, tunnel_t *owner, line_t *line,
                                                LineTaskFnNoBuf task)
{
    assert(lineIsAlive(line) && lineIsOnCurrentWorker(line));
    assert(owner != NULL && task != NULL);
    if (replay->branch == NULL || replay->closing)
        return kFallbackReplayGone;
    assert(! replay->initializing && replay->startup);
    replay->startup = false;

    if (replay->config->delay_ms != 0)
        return fallbackReplaySchedule(replay, owner, line, task);

    sbuf_t *batch = fallbackReplayTakeBatch(replay, lineGetBufferPool(line));
    if (batch == NULL)
        return kFallbackReplayOk;
    return fallbackReplayDispatch(replay, owner, line, batch, task);
}

fallback_replay_result_e fallbackReplaySubmit(fallback_replay_t *replay, tunnel_t *owner, line_t *line, sbuf_t *payload,
                                              LineTaskFnNoBuf task)
{
    assert(lineIsAlive(line) && lineIsOnCurrentWorker(line));
    assert(owner != NULL && payload != NULL && task != NULL);
    if (replay->branch == NULL || replay->closing)
    {
        lineReuseBuffer(line, payload);
        return kFallbackReplayGone;
    }

    if (replay->config->delay_ms == 0 && ! replay->startup &&
        (! replay->dispatching || replay->config->zero_delay_mode == kFallbackReplayInlineNested) &&
        ! replay->scheduled && bufferqueueGetBufCount(&replay->pending) == 0)
        return fallbackReplayDispatch(replay, owner, line, payload, task);

    if (! fallbackReplayBatchFits(replay, lineGetBufferPool(line), sbufGetLength(payload)) ||
        ! bufferqueueTryPushBack(&replay->pending, &payload))
    {
        lineReuseBuffer(line, payload);
        return kFallbackReplayRefused;
    }
    return fallbackReplaySchedule(replay, owner, line, task);
}

fallback_replay_result_e fallbackReplayOnTask(fallback_replay_t *replay, tunnel_t *owner, line_t *line,
                                              LineTaskFnNoBuf task)
{
    assert(lineIsAlive(line) && lineIsOnCurrentWorker(line));
    assert(owner != NULL && task != NULL);
    if (replay->branch == NULL || replay->closing)
        return kFallbackReplayGone;
    replay->scheduled = false;
    if (replay->startup || replay->dispatching)
        return kFallbackReplayOk;

    sbuf_t *batch = fallbackReplayTakeBatch(replay, lineGetBufferPool(line));
    if (batch == NULL)
        return kFallbackReplayOk;
    return fallbackReplayDispatch(replay, owner, line, batch, task);
}

fallback_replay_result_e fallbackReplayDrainOne(fallback_replay_t *replay, tunnel_t *owner, line_t *line,
                                                LineTaskFnNoBuf task, bool *dispatched)
{
    assert(lineIsAlive(line) && lineIsOnCurrentWorker(line));
    assert(owner != NULL && task != NULL && dispatched != NULL);
    *dispatched = false;
    if (replay->branch == NULL || replay->closing)
        return kFallbackReplayGone;
    assert(replay->config->zero_delay_mode == kFallbackReplayCallerDriven);
    if (replay->startup || replay->dispatching)
        return kFallbackReplayOk;
    if (replay->config->delay_ms != 0)
        return fallbackReplaySchedule(replay, owner, line, task);

    sbuf_t *payload = bufferqueuePopFront(&replay->pending);
    if (payload == NULL)
        return kFallbackReplayOk;
    *dispatched = true;
    return fallbackReplayDispatch(replay, owner, line, payload, task);
}

fallback_replay_result_e fallbackReplayCloseFromPrev(fallback_replay_t *replay, line_t *line, bool *send_finish)
{
    assert(lineIsAlive(line) && lineIsOnCurrentWorker(line));
    assert(send_finish != NULL);
    *send_finish = false;
    if (replay->branch == NULL || replay->closing)
        return kFallbackReplayGone;

    replay->closing         = true;
    replay->branch_finished = false;
    buffer_pool_t *pool     = lineGetBufferPool(line);
    sbuf_t        *batch    = NULL;
    if (replay->initializing)
        fallbackReplayDiscardPending(replay, pool);
    else
        batch = fallbackReplayTakeBatch(replay, pool);

    if (batch != NULL)
    {
        if (! lineCallWithRefWithBuf(line, tunnelUpStreamPayload, replay->branch, batch))
            return kFallbackReplayGone;
        if (replay->branch == NULL)
            return kFallbackReplayGone;
    }
    *send_finish = ! replay->branch_finished;
    return kFallbackReplayOk;
}

bool fallbackReplayAbsorbBranchFinish(fallback_replay_t *replay)
{
    if (replay->branch == NULL || ! replay->closing)
        return false;
    replay->branch_finished = true;
    return true;
}

void fallbackReplayDestroy(fallback_replay_t *replay, buffer_pool_t *pool)
{
    fallbackReplayDiscardPending(replay, pool);
    bufferqueueDestroy(&replay->pending);
    memoryZero(replay, sizeof(*replay));
}
