/* Nine-worker startup/shutdown, owner-zero loop cleanup, atomic barriers and the original failure-injection seams. One
 * buffer-disposal observer belongs to this executable. CTest: waterwall.worker_context_helpers_unit; see the driver for
 * ordering and CLI. */
#include "worker_fixture.h"

#define watchBufferDisposal watchWorkerBufferDisposalLocal
#include "fixtures/failure/buffer_disposal_probe.h"
#undef watchBufferDisposal
void watchBufferDisposal(sbuf_t *buf, atomic_uint *counter)
{
    watchWorkerBufferDisposalLocal(buf, counter);
}
const ww_lifecycle_context_t *testShutdownContext(void)
{
    static const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleProcessShutdown,
        .close_policy = kWwLifecycleCloseGraceful,
    };
    return &context;
}

void teardownCurrentWorker(worker_t *worker)
{
    require(workerInstallApplicationQuiesceRequest(worker, testShutdownContext()) != kWorkerQuiesceRequestUnavailable,
            "failed to install worker-0 application quiesce request");
    workerPerformQuiesce(worker, testShutdownContext());
    require(workerRequestDrain(worker), "failed to request current-worker drain");
    workerPerformDrain(worker, testShutdownContext());
    require(workerRequestTeardown(worker), "failed to request current-worker teardown");
    workerPerformTeardown(worker);
}

void initTestGlobalState(void)
{
    static char            log_off[]         = "OFF";
    ww_construction_data_t init_data         = {0};
    init_data.workers_count                  = 9;
    init_data.ram_profile                    = 4;
    init_data.mtu_size                       = 1500;
    init_data.internal_logger_data.log_level = log_off;
    init_data.core_logger_data.log_level     = log_off;
    init_data.network_logger_data.log_level  = log_off;
    init_data.dns_logger_data.log_level      = log_off;

    require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create worker-context fixture");
}

void shutdownTestGlobalState(void)
{
    for (unsigned int wid = 1; wid < getWorkersCount(); ++wid)
    {
        require(workerExitJoin(getWorker(wid)), "failed to stop a test worker");
    }

    /*
     * Worker 0 is bound to this test thread and is therefore never joined.
     * Release its event-loop resources explicitly so the c-ares channel is
     * cleaned before destroyGlobalState() tears down the global library.
     */
    if (! atomicLoadExplicit(&getWorker(0)->resources_destroyed, memory_order_relaxed))
    {
        teardownCurrentWorker(getWorker(0));
    }
    destroyGlobalState();
}

WTHREAD_ROUTINE(messagePoolForeignRoutine)
{
    require(! currentThreadIsEventWorker(), "foreign message-pool thread acquired a worker identity");
    if (userdata != NULL)
    {
        workerMessagePoolRelease(userdata);
    }
    void *record = workerMessagePoolAcquire(sizeof(worker_msg_t));
    workerMessagePoolRelease(record);
    return 0;
}

atomic_int  g_enqueue_pause_stage = ATOMIC_VAR_INIT(-1);
atomic_int  g_enqueue_pause_wid   = ATOMIC_VAR_INIT(-1);
atomic_bool g_force_timed_rearm_refusal;
atomic_bool g_enqueue_seam_reached;
atomic_bool g_enqueue_seam_release;
atomic_int  g_enqueue_seam_hits;
void        workerMessageEnqueueTestSeam(worker_t *worker, worker_message_enqueue_test_stage_e stage)
{
    if ((int) worker->wid != atomicLoadExplicit(&g_enqueue_pause_wid, memory_order_acquire) ||
        (int) stage != atomicLoadExplicit(&g_enqueue_pause_stage, memory_order_acquire))
    {
        return;
    }

    atomicAddExplicit(&g_enqueue_seam_hits, 1, memory_order_acq_rel);
    atomicStoreExplicit(&g_enqueue_seam_reached, true, memory_order_release);
    while (! atomicLoadExplicit(&g_enqueue_seam_release, memory_order_acquire))
    {
        YIELD_THREAD();
    }
}

void workerMessageTimedRearmTestSeam(worker_t *worker, uint64_t *deadline_us)
{
    if (! atomicExchangeExplicit(&g_force_timed_rearm_refusal, false, memory_order_acq_rel))
    {
        return;
    }

    *deadline_us = wloopNowUS(worker->loop) + 1000000U;
    require(wloopRequestQuiesce(worker->loop), "timed rearm seam could not close normal admission");
}

static void workerLoopNestedCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    worker_loop_blocker_t *blocker = arg1;
    discard                worker;
    discard                arg2;
    discard                arg3;
    atomicAddExplicit(&blocker->nested_runs, 1, memory_order_relaxed);
}

static void workerLoopNestedCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    worker_loop_blocker_t *blocker = arg1;
    discard                arg2;
    discard                arg3;
    discard                reason;
    atomicAddExplicit(&blocker->nested_cleanups, 1, memory_order_relaxed);
}

void workerLoopBlockerCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                worker;
    discard                arg2;
    discard                arg3;
    worker_loop_blocker_t *blocker = arg1;
    atomicStoreExplicit(&blocker->entered, true, memory_order_release);
    while (! atomicLoadExplicit(&blocker->release, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    if (blocker->run_nested_after_close)
    {
        sendWorkerMessageWithCleanup(worker->wid,
                                     (WorkerMessageCallback) workerLoopNestedCallback,
                                     workerLoopNestedCleanup,
                                     blocker,
                                     NULL,
                                     NULL);
    }
}

void waitForAtomicBool(const atomic_bool *value, const char *message)
{
    for (uint32_t attempt = 0; attempt < 5000U; ++attempt)
    {
        if (atomicLoadExplicit((atomic_bool *) value, memory_order_acquire))
        {
            return;
        }
        wwSleepMS(1);
    }
    require(false, message);
}

#ifdef WW_WORKER_MESSAGE_LINK_WRAP
atomic_bool g_fail_wakeup_post;
#endif
