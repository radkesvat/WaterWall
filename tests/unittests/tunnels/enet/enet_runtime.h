#pragma once

/*
 * WaterWall runtime for the ENet node tests: one worker, loggers off, core MTU 1500.
 *
 * The test's own thread acts as worker 0, as in the Kcp session fixture. The worker loop is never left running:
 * a test either drives sessions with an explicit clock, or steps the loop with wloopProcessEvents().
 */

#include "wwapi.h"

#include "test_assert.h"
#include "wevent.h"

#define enetRequire(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static inline void enetRuntimeStart(void)
{
    static char            log_off[]    = "OFF";
    ww_construction_data_t init         = {.workers_count = 1, .ram_profile = 4, .mtu_size = 1500};
    init.internal_logger_data.log_level = log_off;
    init.core_logger_data.log_level     = log_off;
    init.network_logger_data.log_level  = log_off;
    init.dns_logger_data.log_level      = log_off;
    enetRequire(wwStartupSucceeded(createGlobalState(init)), "worker runtime construction failed");
    atomicStoreExplicit(&getWorkerLoop(0)->status, WLOOP_STATUS_RUNNING, memory_order_release);
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
}

static inline void enetRuntimeStop(void)
{
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    enetRequire(workerInstallApplicationQuiesceRequest(getWorker(0), context) != kWorkerQuiesceRequestUnavailable,
                "worker quiescence failed");
    workerPerformQuiesce(getWorker(0), context);
    enetRequire(workerRequestDrain(getWorker(0)), "worker drain refused");
    workerPerformDrain(getWorker(0), context);
    enetRequire(workerRequestTeardown(getWorker(0)), "worker teardown refused");
    workerPerformTeardown(getWorker(0));
    destroyGlobalState();
}
