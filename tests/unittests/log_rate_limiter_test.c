#include "loggers/log_rate_limiter.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void testAggregateWindow(void)
{
    log_rate_limiter_t limiter = {0};

    log_rate_limiter_report_t first = logRateLimiterRecordAt(&limiter, 1000, 0);
    require(! first.should_log, "first event emitted a report");
    require(limiter.total == 1, "first event did not increment total");
    require(limiter.pending == 1, "first event did not increment pending");

    require(! logRateLimiterRecordAt(&limiter, 1000, 999).should_log, "event inside window emitted a report");

    log_rate_limiter_report_t report = logRateLimiterRecordAt(&limiter, 1000, 1000);
    require(report.should_log, "interval boundary did not emit a report");
    require(report.events == 3, "aggregate report returned the wrong event count");
    require(report.total == 3, "aggregate report returned the wrong lifetime total");
    require(report.elapsed_ms == 1000, "aggregate report returned the wrong elapsed time");
    require(limiter.pending == 0, "aggregate report did not drain pending events");
}

static void testAggregateWindowsStayIndependent(void)
{
    log_rate_limiter_t limiter = {0};

    require(! logRateLimiterRecordAt(&limiter, 1000, 1000).should_log, "first event emitted a report");
    require(logRateLimiterRecordAt(&limiter, 1000, 2000).should_log, "first window did not report");
    require(! logRateLimiterRecordAt(&limiter, 1000, 2100).should_log, "second window reported early");

    log_rate_limiter_report_t report = logRateLimiterRecordAt(&limiter, 1000, 3500);
    require(report.should_log, "second window did not report");
    require(report.events == 2, "second window included events from the first window");
    require(report.total == 4, "second window returned the wrong lifetime total");
    require(report.elapsed_ms == 1500, "second window returned the wrong elapsed time");
}

static void testFlushDrainsAndRearms(void)
{
    log_rate_limiter_t limiter = {0};

    require(! logRateLimiterRecordAt(&limiter, 1000, 5000).should_log, "first event emitted a report");
    require(! logRateLimiterRecordAt(&limiter, 1000, 5200).should_log, "event inside window emitted a report");

    log_rate_limiter_report_t flush = logRateLimiterFlush(&limiter);
    require(flush.should_log, "flush did not report pending events");
    require(flush.events == 2, "flush returned the wrong pending count");
    require(flush.total == 2, "flush returned the wrong lifetime total");
    require(! logRateLimiterFlush(&limiter).should_log, "empty flush emitted a report");

    require(! logRateLimiterRecordAt(&limiter, 1000, 9000).should_log, "first event after flush was not re-armed");
}

static void testClockRollbackRearmsWindow(void)
{
    log_rate_limiter_t limiter = {0};

    require(! logRateLimiterRecordAt(&limiter, 1000, 5000).should_log, "first event emitted a report");
    require(! logRateLimiterRecordAt(&limiter, 1000, 4000).should_log, "clock rollback emitted a report");
    require(! logRateLimiterRecordAt(&limiter, 1000, 4999).should_log, "re-armed window reported early");

    log_rate_limiter_report_t report = logRateLimiterRecordAt(&limiter, 1000, 5000);
    require(report.should_log, "re-armed window did not report at its boundary");
    require(report.events == 4, "clock rollback lost pending events");
}

static void testCountersSaturate(void)
{
    log_rate_limiter_t limiter = {
        .total             = UINT64_MAX,
        .pending           = UINT64_MAX,
        .window_started_ms = 0,
        .window_started    = true,
    };

    log_rate_limiter_report_t report = logRateLimiterRecordAt(&limiter, 1000, 1000);
    require(report.should_log, "saturated limiter did not report");
    require(report.events == UINT64_MAX, "pending counter wrapped");
    require(report.total == UINT64_MAX, "lifetime counter wrapped");
}

static void testAtomicGate(void)
{
    atomic_log_rate_limiter_t limiter;
    atomicLogRateLimiterInitialize(&limiter);

    require(atomicLogRateLimiterShouldLogAt(&limiter, 1000, 0), "first atomic event was suppressed");
    require(! atomicLogRateLimiterShouldLogAt(&limiter, 1000, 999), "atomic gate opened inside interval");
    require(atomicLogRateLimiterShouldLogAt(&limiter, 1000, 1000), "atomic gate stayed closed at boundary");
    require(atomicLogRateLimiterShouldLogAt(&limiter, 1000, 500), "clock rollback did not reopen atomic gate");
    require(! atomicLogRateLimiterShouldLogAt(&limiter, 1000, 500), "same timestamp reopened atomic gate");

    atomicLogRateLimiterInitialize(&limiter);
    require(atomicLogRateLimiterShouldLogAt(&limiter, 1, UINT64_MAX), "maximum timestamp was suppressed");
    require(! atomicLogRateLimiterShouldLogAt(&limiter, 1, UINT64_MAX), "maximum timestamp reopened atomic gate");
}

int main(void)
{
    testAggregateWindow();
    testAggregateWindowsStayIndependent();
    testFlushDrainsAndRearms();
    testClockRollbackRearmsWindow();
    testCountersSaturate();
    testAtomicGate();
    return 0;
}
