#include "log_rate_limiter.h"

#include "wtime.h"

#include <assert.h>
#include <limits.h>

static uint64_t logRateLimiterNowMs(void)
{
    return getTimeOfDayMS();
}

static void logRateLimiterIncrement(uint64_t *value)
{
    if (*value != UINT64_MAX)
    {
        *value += 1U;
    }
}

log_rate_limiter_report_t logRateLimiterRecord(log_rate_limiter_t *limiter, uint64_t interval_ms)
{
    return logRateLimiterRecordAt(limiter, interval_ms, logRateLimiterNowMs());
}

log_rate_limiter_report_t logRateLimiterRecordAt(log_rate_limiter_t *limiter, uint64_t interval_ms, uint64_t now_ms)
{
    assert(limiter != NULL);
    assert(interval_ms > 0);

    log_rate_limiter_report_t report = {0};

    logRateLimiterIncrement(&limiter->total);
    logRateLimiterIncrement(&limiter->pending);

    if (! limiter->window_started)
    {
        limiter->window_started    = true;
        limiter->window_started_ms = now_ms;
        return report;
    }

    if (now_ms < limiter->window_started_ms)
    {
        /* Re-arm after a wrapping or adjusted injected clock. */
        limiter->window_started_ms = now_ms;
        return report;
    }

    const uint64_t elapsed_ms = now_ms - limiter->window_started_ms;
    if (elapsed_ms < interval_ms)
    {
        return report;
    }

    report.should_log = true;
    report.events     = limiter->pending;
    report.total      = limiter->total;
    report.elapsed_ms = elapsed_ms;

    limiter->pending           = 0;
    limiter->window_started_ms = now_ms;
    return report;
}

log_rate_limiter_report_t logRateLimiterFlush(log_rate_limiter_t *limiter)
{
    assert(limiter != NULL);

    log_rate_limiter_report_t report = {0};
    if (limiter->pending != 0)
    {
        report.should_log = true;
        report.events     = limiter->pending;
        report.total      = limiter->total;
    }

    limiter->pending           = 0;
    limiter->window_started_ms = 0;
    limiter->window_started    = false;
    return report;
}

void atomicLogRateLimiterInitialize(atomic_log_rate_limiter_t *limiter)
{
    assert(limiter != NULL);
    atomicStoreU64Relaxed(&limiter->last_report_token, 0);
}

bool atomicLogRateLimiterShouldLog(atomic_log_rate_limiter_t *limiter, uint64_t interval_ms)
{
    return atomicLogRateLimiterShouldLogAt(limiter, interval_ms, logRateLimiterNowMs());
}

bool atomicLogRateLimiterShouldLogAt(atomic_log_rate_limiter_t *limiter, uint64_t interval_ms, uint64_t now_ms)
{
    assert(limiter != NULL);
    assert(interval_ms > 0);

    /* Store timestamp + 1 so zero remains the unarmed value. */
    const uint64_t desired_token  = now_ms == UINT64_MAX ? UINT64_MAX : now_ms + 1U;
    uint64_t       observed_token = atomicLoadU64Relaxed(&limiter->last_report_token);

    for (;;)
    {
        if (observed_token == UINT64_MAX && now_ms == UINT64_MAX)
        {
            return false;
        }

        const uint64_t observed_ms = observed_token == 0 ? 0 : observed_token - 1U;
        if (observed_token != 0 && now_ms >= observed_ms && now_ms - observed_ms < interval_ms)
        {
            return false;
        }

        if (atomicCompareExchangeU64(&limiter->last_report_token, &observed_token, desired_token))
        {
            return true;
        }
    }
}
