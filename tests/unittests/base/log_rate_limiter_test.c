/*
 * Covers: log rate limiter; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testAggregateWindow, testAggregateWindowsStayIndependent, testFlushDrainsAndRearms,
 * testClockRollbackRearmsWindow, testCountersSaturate, testImmediateAggregateWindows,
 * testImmediateLimitersStayIndependent, testImmediateRollbackAndFlush, testImmediateCountersSaturate,
 * testAtomicGate
 * Checks: Assertion labels include: first event emitted a report; first event did not increment total;
 * first event did not increment pending; event inside window emitted a report
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.log_rate_limiter_unit
 */
#include "loggers/log_rate_limiter.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

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

static void testImmediateAggregateWindows(void)
{
    log_rate_limiter_t limiter = {0};

    log_rate_limiter_report_t first = logRateLimiterRecordImmediateAt(&limiter, 1000, 0);
    require(first.should_log, "first immediate event was suppressed");
    require(first.events == 1 && first.total == 1, "first immediate report returned incorrect counts");
    require(first.elapsed_ms == 0, "first immediate report returned nonzero elapsed time");
    require(limiter.pending == 0, "first immediate report did not drain pending events");
    require(! logRateLimiterRecordImmediateAt(&limiter, 1000, 0).should_log, "same timestamp emitted another report");
    require(! logRateLimiterRecordImmediateAt(&limiter, 1000, 999).should_log, "immediate limiter reported early");

    log_rate_limiter_report_t report = logRateLimiterRecordImmediateAt(&limiter, 1000, 1000);
    require(report.should_log, "immediate limiter did not report at interval boundary");
    require(report.events == 3 && report.total == 4, "immediate report lost suppressed events or counted first twice");
    require(report.elapsed_ms == 1000 && limiter.pending == 0, "immediate report did not settle its window");

    require(! logRateLimiterRecordImmediateAt(&limiter, 1000, 1001).should_log,
            "second immediate window reported early");
    report = logRateLimiterRecordImmediateAt(&limiter, 1000, 3000);
    require(report.should_log && report.events == 2 && report.total == 6, "second immediate window had wrong counts");
    require(report.elapsed_ms == 2000, "second immediate window returned wrong elapsed time");
}

static void testImmediateLimitersStayIndependent(void)
{
    log_rate_limiter_t first  = {0};
    log_rate_limiter_t second = {0};

    require(logRateLimiterRecordImmediateAt(&first, 1000, 0).should_log, "first limiter did not report immediately");
    require(logRateLimiterRecordImmediateAt(&second, 1000, 10).should_log,
            "second limiter did not report independently");
    require(! logRateLimiterRecordImmediateAt(&first, 1000, 500).should_log, "first limiter reported early");
    require(! logRateLimiterRecordImmediateAt(&second, 1000, 1000).should_log,
            "second limiter borrowed first deadline");

    log_rate_limiter_report_t report = logRateLimiterRecordImmediateAt(&first, 1000, 1000);
    require(report.should_log && report.events == 2 && report.total == 3, "first limiter shared counts or deadline");
    report = logRateLimiterRecordImmediateAt(&second, 1000, 1010);
    require(report.should_log && report.events == 2 && report.total == 3, "second limiter shared counts or deadline");
}

static void testImmediateRollbackAndFlush(void)
{
    log_rate_limiter_t limiter = {0};

    require(logRateLimiterRecordImmediateAt(&limiter, 1000, 5000).should_log, "first immediate event was suppressed");
    require(! logRateLimiterRecordImmediateAt(&limiter, 1000, 4000).should_log,
            "immediate clock rollback emitted report");
    require(! logRateLimiterRecordImmediateAt(&limiter, 1000, 4999).should_log,
            "immediate rollback window reported early");
    log_rate_limiter_report_t report = logRateLimiterRecordImmediateAt(&limiter, 1000, 5000);
    require(report.should_log && report.events == 3 && report.total == 4, "immediate rollback lost pending events");
    require(report.elapsed_ms == 1000, "immediate rollback did not re-arm the window");

    require(! logRateLimiterRecordImmediateAt(&limiter, 1000, 5500).should_log,
            "immediate limiter reported before flush");
    report = logRateLimiterFlush(&limiter);
    require(report.should_log && report.events == 1 && report.total == 5, "flush lost immediate limiter counts");
    require(! logRateLimiterFlush(&limiter).should_log, "empty immediate limiter flush emitted report");
    report = logRateLimiterRecordImmediateAt(&limiter, 1000, 8000);
    require(report.should_log && report.events == 1 && report.total == 6, "first event after flush was not immediate");
    require(report.elapsed_ms == 0, "first immediate event after flush retained old elapsed time");
}

static void testImmediateCountersSaturate(void)
{
    log_rate_limiter_t limiter = {.total = UINT64_MAX, .pending = UINT64_MAX};

    log_rate_limiter_report_t report = logRateLimiterRecordImmediateAt(&limiter, 1000, 0);
    require(report.should_log && report.events == UINT64_MAX && report.total == UINT64_MAX,
            "immediate report wrapped saturated counters");
    require(limiter.pending == 0, "saturated immediate report did not drain pending events");
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
    testCaseSet("log_rate_limiter_test");
    testAggregateWindow();
    testAggregateWindowsStayIndependent();
    testFlushDrainsAndRearms();
    testClockRollbackRearmsWindow();
    testCountersSaturate();
    testImmediateAggregateWindows();
    testImmediateLimitersStayIndependent();
    testImmediateRollbackAndFlush();
    testImmediateCountersSaturate();
    testAtomicGate();
    return 0;
}
