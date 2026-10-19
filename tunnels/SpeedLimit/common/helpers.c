#include "structure.h"

#include "loggers/network_logger.h"

static uint64_t speedlimitNowMs(line_t *line)
{
    return wloopNowMS(getWorkerLoop(lineGetWID(line)));
}

static rate_bucket_t speedlimitReadBucket(const speedlimit_bucket_t *bucket)
{
    return (rate_bucket_t) {.credit         = bucket->tokens_units / kSpeedLimitUnitsPerByte,
                            .last_refill_ms = bucket->last_refill_ms,
                            .remainder      = (uint16_t) (bucket->tokens_units % kSpeedLimitUnitsPerByte),
                            .has_clock      = bucket->has_clock || bucket->last_refill_ms != 0};
}

static void speedlimitWriteBucket(speedlimit_bucket_t *bucket, const rate_bucket_t *value)
{
    bucket->tokens_units   = value->credit * kSpeedLimitUnitsPerByte + value->remainder;
    bucket->last_refill_ms = value->last_refill_ms;
    bucket->has_clock      = value->has_clock;
}

/* Synchronization is adapter policy. One lock serializes the two atomic fields
 * so clock publication cannot precede its corresponding shared credit refill. */
static speedlimit_bucket_t *speedlimitAcquireBucket(speedlimit_tstate_t *state, speedlimit_bucket_t *global)
{
    while (atomicFlagTestAndSet(&state->global_bucket.lock))
    {
    }
    *global = (speedlimit_bucket_t) {.tokens_units   = atomicLoadU64Relaxed(&state->global_bucket.tokens_units),
                                     .last_refill_ms = atomicLoadU64Relaxed(&state->global_bucket.last_refill_ms),
                                     .has_clock      = state->global_bucket.has_clock};
    return global;
}

static speedlimit_bucket_t *speedlimitLocalBucket(tunnel_t *tunnel, line_t *line)
{
    speedlimit_tstate_t *state = tunnelGetState(tunnel);
    return state->limit_mode == kSpeedLimitLimitModePerWorker
               ? &state->worker_buckets[lineGetWID(line)]
               : &((speedlimit_lstate_t *) lineGetState(line, tunnel))->line_bucket;
}

static void speedlimitReleaseBucket(speedlimit_tstate_t *state, const speedlimit_bucket_t *bucket)
{
    if (state->limit_mode == kSpeedLimitLimitModeAllLines)
    {
        atomicStoreU64Relaxed(&state->global_bucket.tokens_units, bucket->tokens_units);
        atomicStoreU64Relaxed(&state->global_bucket.last_refill_ms, bucket->last_refill_ms);
        state->global_bucket.has_clock = bucket->has_clock;
        atomicFlagClear(&state->global_bucket.lock);
    }
}

static speedlimit_bucket_t *speedlimitBucket(tunnel_t *tunnel, line_t *line, speedlimit_bucket_t *global)
{
    speedlimit_tstate_t *state = tunnelGetState(tunnel);
    if (state->limit_mode != kSpeedLimitLimitModeAllLines)
        return speedlimitLocalBucket(tunnel, line);
    return speedlimitAcquireBucket(state, global);
}

uint64_t speedlimitPeekAvailableUnits(tunnel_t *tunnel, line_t *line)
{
    speedlimit_tstate_t *state = tunnelGetState(tunnel);
    speedlimit_bucket_t  global;
    speedlimit_bucket_t *bucket = speedlimitBucket(tunnel, line, &global);
    rate_bucket_t        value  = speedlimitReadBucket(bucket);
    ratebucketRefill(
        &value, state->bytes_per_sec, state->bytes_per_sec, state->recharge_interval_ms, speedlimitNowMs(line));
    speedlimitWriteBucket(bucket, &value);
    uint64_t units = bucket->tokens_units;
    speedlimitReleaseBucket(state, bucket);
    return units;
}

size_t speedlimitGrantBytes(tunnel_t *tunnel, line_t *line, size_t requested, bool allow_partial)
{
    if (requested == 0)
        return 0;
    speedlimit_tstate_t *state = tunnelGetState(tunnel);
    speedlimit_bucket_t  global;
    speedlimit_bucket_t *bucket = speedlimitBucket(tunnel, line, &global);
    rate_bucket_t        value  = speedlimitReadBucket(bucket);
    ratebucketRefill(
        &value, state->bytes_per_sec, state->bytes_per_sec, state->recharge_interval_ms, speedlimitNowMs(line));
    size_t granted = (size_t) ratebucketGrant(&value, requested, allow_partial);
    speedlimitWriteBucket(bucket, &value);
    speedlimitReleaseBucket(state, bucket);
    return granted;
}

uint32_t speedlimitGetRetryDelayMs(tunnel_t *tunnel, line_t *line)
{
    speedlimit_tstate_t *state = tunnelGetState(tunnel);
    speedlimit_bucket_t  global;
    speedlimit_bucket_t *bucket = speedlimitBucket(tunnel, line, &global);
    rate_bucket_t        value  = speedlimitReadBucket(bucket);
    uint64_t             now    = speedlimitNowMs(line);
    ratebucketRefill(&value, state->bytes_per_sec, state->bytes_per_sec, state->recharge_interval_ms, now);
    uint64_t delay = ratebucketRetryMs(&value, state->bytes_per_sec, state->recharge_interval_ms, now, 1);
    speedlimitWriteBucket(bucket, &value);
    speedlimitReleaseBucket(state, bucket);
    assert(delay <= INT_MAX);
    return delay == 0 ? kSpeedLimitImmediateMs : (uint32_t) delay;
}

bool speedlimitScheduleUpstreamDrain(speedlimit_lstate_t *state, uint32_t delay_ms)
{
    assert(delay_ms > 0);
    return trafficshaperSchedule(&state->up, delay_ms);
}

bool speedlimitScheduleDownstreamDrain(speedlimit_lstate_t *state, uint32_t delay_ms)
{
    assert(delay_ms > 0);
    return trafficshaperSchedule(&state->down, delay_ms);
}

void speedlimitCloseLineOnDrainFailure(speedlimit_lstate_t *state, sbuf_t *detached)
{
    tunnel_t *tunnel = state->tunnel;
    line_t   *line   = state->line;
    lineRef(line);
    if (detached != NULL)
        lineReuseBuffer(line, detached);
    speedlimitLinestateDestroy(state);
    tunnelNextUpStreamFinish(tunnel, line);
    if (lineIsAlive(line))
        tunnelPrevDownStreamFinish(tunnel, line);
    lineUnref(line);
}

static traffic_shaper_preview_t speedlimitPreview(void *context, size_t requested, bool queued)
{
    discard                 queued;
    speedlimit_direction_t *direction = context;
    speedlimit_lstate_t    *state     = direction->state;
    uint64_t                units     = speedlimitPeekAvailableUnits(state->tunnel, state->line);
    size_t                  bytes     = (size_t) min((uint64_t) requested, units / kSpeedLimitUnitsPerByte);
    return (traffic_shaper_preview_t) {
        bytes, requested != 0 && bytes == 0 ? speedlimitGetRetryDelayMs(state->tunnel, state->line) : 0, false};
}

static traffic_shaper_commit_t speedlimitCommit(void *context, size_t bytes, bool queued, bool remaining)
{
    discard                 queued;
    discard                 remaining;
    speedlimit_direction_t *direction = context;
    speedlimit_lstate_t    *state     = direction->state;
    return speedlimitGrantBytes(state->tunnel, state->line, bytes, false) == bytes ? kTrafficShaperForward
                                                                                   : kTrafficShaperWait;
}

static void speedlimitForward(void *context, sbuf_t *buffer)
{
    speedlimit_direction_t *direction = context;
    speedlimit_lstate_t    *state     = direction->state;
    if (direction->upstream)
        tunnelNextUpStreamPayload(state->tunnel, state->line, buffer);
    else
        tunnelPrevDownStreamPayload(state->tunnel, state->line, buffer);
}

static void speedlimitPressure(void *context, bool paused)
{
    speedlimit_direction_t *direction = context;
    speedlimit_lstate_t    *state     = direction->state;
    if (direction->upstream)
    {
        if (paused)
            tunnelPrevDownStreamPause(state->tunnel, state->line);
        else
            tunnelPrevDownStreamResume(state->tunnel, state->line);
    }
    else
    {
        if (paused)
            tunnelNextUpStreamPause(state->tunnel, state->line);
        else
            tunnelNextUpStreamResume(state->tunnel, state->line);
    }
}

static void speedlimitClose(void *context)
{
    speedlimit_direction_t *direction = context;
    speedlimitCloseLineOnDrainFailure(direction->state, NULL);
}

const traffic_shaper_ops_t speedlimitShaperOps = {.preview  = speedlimitPreview,
                                                  .commit   = speedlimitCommit,
                                                  .forward  = speedlimitForward,
                                                  .pressure = speedlimitPressure,
                                                  .close    = speedlimitClose};
