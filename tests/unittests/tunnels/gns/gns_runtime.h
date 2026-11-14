#pragma once

/*
 * WaterWall runtime for the GNS node tests: one worker, loggers off, core MTU 1500.
 *
 * The test's own thread acts as worker 0, as in the ENet fixture. The worker loop is never left running: a test
 * steps it with gnsTestStep(), which is also what delivers the wakes that GameNetworkingSockets' own threads post.
 * The library reads its own clock, so these tests run in real time: they wait with deadlines and assert no timing.
 */

#include "wwapi.h"

#include "test_assert.h"
#include "wevent.h"

#define gnsRequire(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kGnsTestDeadlineMs = 60000,
};

static inline void gnsTestFirstWake(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg1;
    discard arg2;
    discard arg3;
}

static inline void gnsTestFirstWakeCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg1;
    discard arg2;
    discard arg3;
    discard reason;
}

static inline void gnsTestRuntimeStart(void)
{
    static char            log_off[]    = "OFF";
    ww_construction_data_t init         = {.workers_count = 1, .ram_profile = 4, .mtu_size = 1500};
    init.internal_logger_data.log_level = log_off;
    init.core_logger_data.log_level     = log_off;
    init.network_logger_data.log_level  = log_off;
    init.dns_logger_data.log_level      = log_off;
    gnsRequire(wwStartupSucceeded(createGlobalState(init)), "worker runtime construction failed");
    atomicStoreExplicit(&getWorkerLoop(0)->status, WLOOP_STATUS_RUNNING, memory_order_release);
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    /* A loop that runs makes its wake descriptors when it starts, before any session exists. This loop is only
     * stepped, so it makes them for its first message. Send that message from this thread now; otherwise the first
     * wake of the library's thread would make them while this thread steps the loop. */
    gnsRequire(sendWorkerMessageForceQueueWithCleanup(
                   0, (WorkerMessageCallback) gnsTestFirstWake, gnsTestFirstWakeCancelled, NULL, NULL, NULL) ==
                   kWorkerMessageSubmitAccepted,
               "the worker refused its first message");
    wloopUpdateTime(getWorkerLoop(0));
    discard wloopProcessEvents(getWorkerLoop(0), 0);
}

static inline void gnsTestRuntimeStop(void)
{
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    gnsRequire(workerInstallApplicationQuiesceRequest(getWorker(0), context) != kWorkerQuiesceRequestUnavailable,
               "worker quiescence failed");
    workerPerformQuiesce(getWorker(0), context);
    gnsRequire(workerRequestDrain(getWorker(0)), "worker drain refused");
    workerPerformDrain(getWorker(0), context);
    gnsRequire(workerRequestTeardown(getWorker(0)), "worker teardown refused");
    workerPerformTeardown(getWorker(0));
    destroyGlobalState();
}

/* Runs what is due on worker 0: timers and the messages that other threads posted to it. */
static inline void gnsTestStep(void)
{
    wloopUpdateTime(getWorkerLoop(0));
    discard wloopProcessEvents(getWorkerLoop(0), 0);
}

static inline uint64_t gnsTestNowMs(void)
{
    return getHRTimeUs() / 1000U;
}
