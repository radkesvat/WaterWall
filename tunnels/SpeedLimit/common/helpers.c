#include "structure.h"

#include "loggers/network_logger.h"

static uint64_t speedlimitNowMs(line_t *l)
{
    return wloopNowMS(getWorkerLoop(lineGetWID(l)));
}

static speedlimit_bucket_t *speedlimitGetWorkerBucket(speedlimit_tstate_t *ts, line_t *l)
{
    return &ts->worker_buckets[lineGetWID(l)];
}

static void speedlimitRefillLocalBucket(const speedlimit_tstate_t *ts, speedlimit_bucket_t *bucket, uint64_t now_ms)
{
    if (bucket->last_refill_ms == 0)
    {
        bucket->last_refill_ms = now_ms;
        return;
    }

    if (now_ms <= bucket->last_refill_ms)
    {
        return;
    }

    uint64_t elapsed_ms = now_ms - bucket->last_refill_ms;
    uint64_t steps      = elapsed_ms / ts->recharge_interval_ms;
    if (steps == 0)
    {
        return;
    }

    uint64_t added_units;
    if (steps > (UINT64_MAX / ts->refill_units_per_step))
    {
        added_units = UINT64_MAX;
    }
    else
    {
        added_units = steps * ts->refill_units_per_step;
    }

    bucket->last_refill_ms += steps * ts->recharge_interval_ms;

    if (bucket->tokens_units >= ts->bucket_capacity_units)
    {
        bucket->tokens_units = ts->bucket_capacity_units;
        return;
    }

    if (added_units >= ts->bucket_capacity_units - bucket->tokens_units)
    {
        bucket->tokens_units = ts->bucket_capacity_units;
        return;
    }

    bucket->tokens_units += added_units;
}

static void speedlimitRefillAtomicBucket(const speedlimit_tstate_t *ts, speedlimit_atomic_bucket_t *bucket,
                                         uint64_t now_ms)
{
    while (true)
    {
        uint64_t last_refill_ms = atomicLoadU64Relaxed(&bucket->last_refill_ms);
        if (last_refill_ms == 0)
        {
            uint64_t expected = 0;
            if (atomicCompareExchangeU64(&bucket->last_refill_ms, &expected, now_ms))
            {
                return;
            }
            continue;
        }

        if (now_ms <= last_refill_ms)
        {
            return;
        }

        uint64_t elapsed_ms = now_ms - last_refill_ms;
        uint64_t steps      = elapsed_ms / ts->recharge_interval_ms;
        if (steps == 0)
        {
            return;
        }

        uint64_t new_last_refill_ms = last_refill_ms + (steps * ts->recharge_interval_ms);
        uint64_t expected_last      = last_refill_ms;
        if (! atomicCompareExchangeU64(&bucket->last_refill_ms, &expected_last, new_last_refill_ms))
        {
            continue;
        }

        uint64_t added_units;
        if (steps > (UINT64_MAX / ts->refill_units_per_step))
        {
            added_units = UINT64_MAX;
        }
        else
        {
            added_units = steps * ts->refill_units_per_step;
        }

        while (true)
        {
            uint64_t old_units = atomicLoadU64Relaxed(&bucket->tokens_units);
            uint64_t new_units = old_units;

            if (old_units < ts->bucket_capacity_units)
            {
                if (added_units >= ts->bucket_capacity_units - old_units)
                {
                    new_units = ts->bucket_capacity_units;
                }
                else
                {
                    new_units = old_units + added_units;
                }
            }

            uint64_t expected_units = old_units;
            if (atomicCompareExchangeU64(&bucket->tokens_units, &expected_units, new_units))
            {
                return;
            }
        }
    }
}

uint64_t speedlimitPeekAvailableUnits(tunnel_t *t, line_t *l)
{
    speedlimit_tstate_t *ts     = tunnelGetState(t);
    uint64_t             now_ms = speedlimitNowMs(l);

    switch (ts->limit_mode)
    {
    case kSpeedLimitLimitModePerWorker: {
        speedlimit_bucket_t *bucket = speedlimitGetWorkerBucket(ts, l);
        speedlimitRefillLocalBucket(ts, bucket, now_ms);
        return bucket->tokens_units;
    }
    case kSpeedLimitLimitModeAllLines:
        speedlimitRefillAtomicBucket(ts, &ts->global_bucket, now_ms);
        return atomicLoadU64Relaxed(&ts->global_bucket.tokens_units);
    case kSpeedLimitLimitModePerLine:
    default: {
        speedlimit_lstate_t *ls = lineGetState(l, t);
        speedlimitRefillLocalBucket(ts, &ls->line_bucket, now_ms);
        return ls->line_bucket.tokens_units;
    }
    }
}

static uint64_t speedlimitPeekLastRefillMs(tunnel_t *t, line_t *l)
{
    speedlimit_tstate_t *ts = tunnelGetState(t);

    switch (ts->limit_mode)
    {
    case kSpeedLimitLimitModePerWorker:
        return speedlimitGetWorkerBucket(ts, l)->last_refill_ms;
    case kSpeedLimitLimitModeAllLines:
        return atomicLoadU64Relaxed(&ts->global_bucket.last_refill_ms);
    case kSpeedLimitLimitModePerLine:
    default:
        return ((speedlimit_lstate_t *) lineGetState(l, t))->line_bucket.last_refill_ms;
    }
}

size_t speedlimitGrantBytes(tunnel_t *t, line_t *l, size_t requested_bytes, bool allow_partial)
{
    speedlimit_tstate_t *ts = tunnelGetState(t);
    if (requested_bytes == 0)
    {
        return 0;
    }

    uint64_t now_ms = speedlimitNowMs(l);

    if (ts->limit_mode == kSpeedLimitLimitModeAllLines)
    {
        speedlimitRefillAtomicBucket(ts, &ts->global_bucket, now_ms);

        while (true)
        {
            uint64_t old_units       = atomicLoadU64Relaxed(&ts->global_bucket.tokens_units);
            uint64_t available_bytes = old_units / kSpeedLimitUnitsPerByte;
            size_t   grant_bytes     = 0;

            if (allow_partial)
            {
                grant_bytes = (size_t) min((uint64_t) requested_bytes, available_bytes);
            }
            else if (available_bytes >= requested_bytes)
            {
                grant_bytes = requested_bytes;
            }

            if (grant_bytes == 0)
            {
                return 0;
            }

            uint64_t consume_units  = ((uint64_t) grant_bytes) * kSpeedLimitUnitsPerByte;
            uint64_t expected_units = old_units;
            if (atomicCompareExchangeU64(&ts->global_bucket.tokens_units, &expected_units, old_units - consume_units))
            {
                return grant_bytes;
            }
        }
    }

    speedlimit_bucket_t *bucket;
    if (ts->limit_mode == kSpeedLimitLimitModePerWorker)
    {
        bucket = speedlimitGetWorkerBucket(ts, l);
    }
    else
    {
        speedlimit_lstate_t *ls = lineGetState(l, t);
        bucket                  = &ls->line_bucket;
    }

    speedlimitRefillLocalBucket(ts, bucket, now_ms);

    uint64_t available_bytes = bucket->tokens_units / kSpeedLimitUnitsPerByte;
    size_t   grant_bytes     = 0;
    if (allow_partial)
    {
        grant_bytes = (size_t) min((uint64_t) requested_bytes, available_bytes);
    }
    else if (available_bytes >= requested_bytes)
    {
        grant_bytes = requested_bytes;
    }

    if (grant_bytes == 0)
    {
        return 0;
    }

    bucket->tokens_units -= ((uint64_t) grant_bytes) * kSpeedLimitUnitsPerByte;
    return grant_bytes;
}

uint32_t speedlimitGetRetryDelayMs(tunnel_t *t, line_t *l)
{
    speedlimit_tstate_t *ts           = tunnelGetState(t);
    uint64_t             now_ms       = speedlimitNowMs(l);
    uint64_t             tokens_units = speedlimitPeekAvailableUnits(t, l);
    uint64_t             last_refill  = speedlimitPeekLastRefillMs(t, l);

    if (tokens_units >= kSpeedLimitUnitsPerByte)
    {
        return kSpeedLimitImmediateMs;
    }

    if (last_refill == 0 || now_ms < last_refill)
    {
        return ts->recharge_interval_ms;
    }

    uint64_t phase_ms = (now_ms - last_refill) % ts->recharge_interval_ms;
    uint64_t wait_ms  = (phase_ms == 0) ? ts->recharge_interval_ms : (ts->recharge_interval_ms - phase_ms);

    if (tokens_units < kSpeedLimitUnitsPerByte)
    {
        uint64_t missing_units = kSpeedLimitUnitsPerByte - tokens_units;
        uint64_t steps_needed  = (missing_units + ts->refill_units_per_step - 1) / ts->refill_units_per_step;
        if (steps_needed > 1)
        {
            wait_ms += (steps_needed - 1) * ts->recharge_interval_ms;
        }
    }

    if (wait_ms == 0 || wait_ms > UINT32_MAX)
    {
        return ts->recharge_interval_ms;
    }

    return (uint32_t) wait_ms;
}

bool speedlimitScheduleUpstreamDrain(speedlimit_lstate_t *ls, uint32_t delay_ms)
{
    if (delay_ms == 0)
    {
        delay_ms = kSpeedLimitImmediateMs;
    }

    if (ls->up_timer != NULL)
    {
        wtimerReset(ls->up_timer, delay_ms);
        return true;
    }

    wtimer_t *timer = wtimerAdd(getWorkerLoop(lineGetWID(ls->line)), speedlimitUpstreamDrainTimerCallback, delay_ms, 1);
    if (timer == NULL)
    {
        // the queue can never be drained again on this line, the caller closes it
        LOGE("SpeedLimit: failed to create the upstream drain timer for this line");
        return false;
    }

    ls->up_timer = timer;
    weventSetUserData(timer, ls);
    return true;
}

bool speedlimitScheduleDownstreamDrain(speedlimit_lstate_t *ls, uint32_t delay_ms)
{
    if (delay_ms == 0)
    {
        delay_ms = kSpeedLimitImmediateMs;
    }

    if (ls->down_timer != NULL)
    {
        wtimerReset(ls->down_timer, delay_ms);
        return true;
    }

    wtimer_t *timer =
        wtimerAdd(getWorkerLoop(lineGetWID(ls->line)), speedlimitDownstreamDrainTimerCallback, delay_ms, 1);
    if (timer == NULL)
    {
        // the queue can never be drained again on this line, the caller closes it
        LOGE("SpeedLimit: failed to create the downstream drain timer for this line");
        return false;
    }

    ls->down_timer = timer;
    weventSetUserData(timer, ls);
    return true;
}

void speedlimitCloseLineOnDrainFailure(speedlimit_lstate_t *ls, sbuf_t *detached_buf)
{
    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    // both sides of this line are initialized and the close below may destroy the line re-entrantly
    lineLock(l);

    if (detached_buf != NULL)
    {
        // this buffer was already removed from its queue and will never be forwarded
        lineReuseBuffer(l, detached_buf);
    }

    // recycles both queues and deletes both timers
    speedlimitLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);

    if (lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}
