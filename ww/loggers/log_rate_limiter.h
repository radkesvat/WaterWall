#pragma once

#include "watomic.h"
#include "wexport.h"

/*
 * A zero-initialized aggregate limiter is ready for use. The caller must
 * serialize access to it. Each recorded event contributes to the lifetime
 * total and to the pending count returned by the next report.
 */
typedef struct log_rate_limiter_s
{
    uint64_t total;
    uint64_t pending;
    uint64_t window_started_ms;
    bool     window_started;
} log_rate_limiter_t;

typedef struct log_rate_limiter_report_s
{
    bool     should_log;
    uint64_t events;
    uint64_t total;
    uint64_t elapsed_ms;
} log_rate_limiter_report_t;

/* Uses the runtime millisecond clock. Clock rollback starts a fresh window. */
WW_EXPORT log_rate_limiter_report_t logRateLimiterRecord(log_rate_limiter_t *limiter, uint64_t interval_ms);

/* Injected-clock variant for callers that already have a timestamp and tests. */
WW_EXPORT log_rate_limiter_report_t logRateLimiterRecordAt(log_rate_limiter_t *limiter, uint64_t interval_ms,
                                                           uint64_t now_ms);

/* Drains pending events once and starts a fresh reporting window. */
WW_EXPORT log_rate_limiter_report_t logRateLimiterFlush(log_rate_limiter_t *limiter);

/*
 * Thread-safe gate for messages that do not need aggregate counts. Initialize
 * it before publication, then share it freely between threads.
 */
typedef struct atomic_log_rate_limiter_s
{
    atomic_ullong last_report_token;
} atomic_log_rate_limiter_t;

WW_EXPORT void atomicLogRateLimiterInitialize(atomic_log_rate_limiter_t *limiter);
WW_EXPORT bool atomicLogRateLimiterShouldLog(atomic_log_rate_limiter_t *limiter, uint64_t interval_ms);
WW_EXPORT bool atomicLogRateLimiterShouldLogAt(atomic_log_rate_limiter_t *limiter, uint64_t interval_ms,
                                               uint64_t now_ms);
