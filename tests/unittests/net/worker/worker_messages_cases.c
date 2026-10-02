/* Transactional queue construction, first-wake rollback, immediate/timed messages, local-batch FIFO/fairness and
 * fork-isolated quiescence/cancellation. CTest: waterwall.worker_context_helpers_unit; see the driver for ordering and
 * CLI. */
#include "worker_fixture.h"

void testWorkerMessageConstructionTransactional(void)
{
    worker_t worker = {0};
    mutexInit(&worker.control_mutex);

    const worker_message_init_test_failure_e failures[] = {
        kWorkerMessageInitFailOuterAllocation,
        kWorkerMessageInitFailQueuedReserve,
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i)
    {
        workerMessagesInitTestSetFailure(failures[i]);
        require(! workerMessagesInit(&worker), "worker-message construction refusal reported success");
        require(worker.message_queue == NULL, "worker-message construction refusal published a partial queue");
        require(! atomicLoadExplicit(&worker.message_admission_open, memory_order_acquire),
                "worker-message construction refusal opened admission");

        require(workerMessagesInit(&worker), "worker-message construction could not retry cleanly");
        require(worker.message_queue != NULL, "successful worker-message construction did not publish its queue");
        require(! atomicLoadExplicit(&worker.message_admission_open, memory_order_acquire),
                "successful construction opened admission before worker startup");
        workerMessagesDestroy(&worker);
        require(worker.message_queue == NULL, "worker-message retry queue did not detach during teardown");
    }

    mutexDestroy(&worker.control_mutex);
}

void testWorkerMessageInitialCapacity(void)
{
    const uint32_t saved_profile = RAM_PROFILE;
    const struct
    {
        uint32_t profile;
        size_t   capacity;
    } cases[] = {
        {kRamProfileS1Memory, 511},
        {kRamProfileS2Memory, 511},
        {kRamProfileM1Memory, 511},
        {kRamProfileM2Memory, 511},
        {kRamProfileL1Memory, 2047},
        {kRamProfileL2Memory, 2047},
    };
    worker_t worker = {0};
    mutexInit(&worker.control_mutex);

    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        GSTATE.ram_profile = cases[i].profile;
        require(workerMessagesInit(&worker), "failed to reserve the profile's initial message queue");
        require(workerMessagesTestQueueCapacity(&worker) == cases[i].capacity,
                "initial message queue capacity does not match its RAM profile");
        require(! atomicLoadExplicit(&worker.message_admission_open, memory_order_acquire),
                "reserving a message queue opened admission");
        workerMessagesDestroy(&worker);
    }

    mutexDestroy(&worker.control_mutex);
    GSTATE.ram_profile = saved_profile;
}

// ---------------------------------------------------------------------------
// Checked accessors
// ---------------------------------------------------------------------------

// Worker messages
// ---------------------------------------------------------------------------

typedef struct message_probe_s
{
    atomic_int ran;
    atomic_int cleaned;
    wid_t      observed_wid;
} message_probe_t;

static message_probe_t g_probe;

static void probeCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg2;
    discard arg3;

    g_probe.observed_wid = worker->wid;
    atomicAddExplicit(&g_probe.ran, 1, memory_order_relaxed);
}

static void probeCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg1;
    discard arg2;
    discard arg3;

    atomicAddExplicit(&g_probe.cleaned, 1, memory_order_relaxed);
}

static void probeReset(void)
{
    atomicStoreRelaxed(&g_probe.ran, 0);
    atomicStoreRelaxed(&g_probe.cleaned, 0);
    g_probe.observed_wid = kInvalidWID;
}

void testTransactionalEnqueueFailureStages(void)
{
    const worker_message_enqueue_test_failure_e failures[] = {
        kWorkerMessageEnqueueFailDequeGrowth,
        kWorkerMessageEnqueueFailWakeupPost,
    };

    for (uint32_t i = 0; i < ARRAY_SIZE(failures); ++i)
    {
        probeReset();
        workerMessagesEnqueueTestSetFailure(failures[i]);
        require(! sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL),
                "transactional worker enqueue fault was reported as accepted");
        require(atomicLoadRelaxed(&g_probe.ran) == 0, "transactional worker enqueue fault ran its callback early");
        require(atomicLoadRelaxed(&g_probe.cleaned) == 1,
                "transactional worker enqueue fault did not clean ownership exactly once");

        probeReset();
        workerMessagesEnqueueTestSetFailure(failures[i]);
        require(sendWorkerMessageForceQueueRetainOnRefusal(
                    1, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL) ==
                    kWorkerMessageSubmitRejectedCallerRetains,
                "retain-on-refusal worker enqueue fault was reported as accepted");
        require(atomicLoadRelaxed(&g_probe.ran) == 0, "retain-on-refusal worker enqueue fault ran its callback early");
        require(atomicLoadRelaxed(&g_probe.cleaned) == 0,
                "retain-on-refusal worker enqueue fault took caller-owned arguments");
    }

    /* The value-record queue has no stable allocation identity. Exercise two
     * indistinguishable payloads around a failed first wake and assert public
     * settlement, rather than peeking into the deque's private storage. */
    /* testOwningWorkerOutsideCallbackQueues() intentionally left one worker-0
     * record pending. Drain it before this exact-settlement fixture resets its
     * shared probe counters. */
    discard wloopProcessEvents(getWorkerLoop(0), 0);
    probeReset();
    workerMessagesEnqueueTestSetFailure(kWorkerMessageEnqueueFailWakeupPost);
    require(sendWorkerMessageForceQueueWithCleanup(
                0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL) ==
                kWorkerMessageSubmitRejectedCleanupRan,
            "first identical value record was not refused after its wake failed");
    require(sendWorkerMessageForceQueueWithCleanup(
                0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "second identical value record was not accepted after first-wake rollback");
    discard wloopProcessEvents(getWorkerLoop(0), 0);
    require(atomicLoadRelaxed(&g_probe.ran) == 1,
            "first-wake rollback did not deliver exactly one later identical value record");
    require(atomicLoadRelaxed(&g_probe.cleaned) == 1,
            "first-wake rollback did not clean exactly its refused identical value record");
}
static void messagePoolTransferCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard         arg3;
    generic_pool_t *pool = worker->message_pool;
    require(currentThreadIsEventWorkerWID(1) && pool != NULL, "message record reached the wrong cache owner");
    const uint32_t expected_len = pool->len > pool->free_threshold ? pool->len - pool->cap / 2 : pool->len;
    workerMessagePoolRelease(arg1);
    require(pool->len == expected_len + 1, "cross-worker return did not enter the receiving worker's cache");
    void *reused = workerMessagePoolAcquire(sizeof(worker_msg_t));
    require(reused == arg1, "receiving worker did not reuse the transferred message record");
    workerMessagePoolRelease(reused);
    atomicStoreExplicit((atomic_bool *) arg2, true, memory_order_release);
}

void testWorkerMessagePoolCrossWorkerReturn(void)
{
    void          *record     = workerMessagePoolAcquire(sizeof(worker_msg_t));
    const uint32_t source_len = getWorker(0)->message_pool->len;
    atomic_bool    complete;
    atomic_init(&complete, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) messagePoolTransferCallback, NULL, record, &complete, NULL) ==
                kWorkerMessageSubmitAccepted,
            "failed to queue a pooled record to another worker");
    waitForAtomicBool(&complete, "cross-worker message record did not settle");
    require(getWorker(0)->message_pool->len == source_len, "receiver returned a record into its source worker's cache");
}

#ifdef WW_WORKER_MESSAGE_LINK_WRAP
static void testTimedRearmRefusalCleansExactlyOnce(void)
{
    probeReset();
    const uint32_t timers_before = getWorkerLoop(0)->ntimers;
    atomicStoreExplicit(&g_force_timed_rearm_refusal, true, memory_order_release);
    require(sendWorkerMessageTimedWithCleanup(
                0, (WorkerMessageCallback) probeCallback, probeCleanup, 1U, NULL, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "failed to arm the timed rearm-refusal fixture");

    wwSleepMS(2);
    for (uint32_t attempt = 0; attempt < 100U && atomicLoadRelaxed(&g_probe.cleaned) == 0; ++attempt)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
    }

    require(atomicLoadRelaxed(&g_probe.ran) == 0, "rearm refusal ran the timed task early");
    require(atomicLoadRelaxed(&g_probe.cleaned) == 1, "rearm refusal did not clean the timed task exactly once");
    require(getWorkerLoop(0)->ntimers == timers_before, "rearm refusal retained the executing one-shot timer");
}

#if defined(HAS_UNIX_FORK)
void testTimedRearmRefusalInIsolatedProcess(void)
{
    pid_t pid = fork();
    require(pid >= 0, "fork failed for timed rearm-refusal case");
    if (pid == 0)
    {
        initTestGlobalState();
        testTimedRearmRefusalCleansExactlyOnce();
        shutdownTestGlobalState();
        _Exit(0);
    }

    int status = 0;
    require(waitpid(pid, &status, 0) == pid, "waitpid failed for timed rearm-refusal case");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "timed rearm-refusal child failed");
}
#endif
#endif

typedef enum
{
    kWorkerMessageBatchBlocker = 1,
    kWorkerMessageBatchA,
    kWorkerMessageBatchB,
    kWorkerMessageBatchUnrelated,
    kWorkerMessageBatchC,
} worker_message_batch_event_e;

typedef struct worker_message_batch_probe_s
{
    atomic_bool release_blocker;
    atomic_bool blocker_entered;
    atomic_bool complete;
    uint32_t    count;
    uint8_t     order[5];
} worker_message_batch_probe_t;

static void workerMessageBatchRecord(worker_message_batch_probe_t *probe, worker_message_batch_event_e event)
{
    require(probe->count < ARRAY_SIZE(probe->order), "worker-message batch fixture recorded too many callbacks");
    probe->order[probe->count++] = (uint8_t) event;
}

static void workerMessageBatchBlocker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    worker_message_batch_probe_t *probe = arg1;
    discard                       arg2;
    discard                       arg3;

    require(worker->wid == 1, "worker-message batch blocker ran on the wrong worker");
    workerMessageBatchRecord(probe, kWorkerMessageBatchBlocker);
    atomicStoreExplicit(&probe->blocker_entered, true, memory_order_release);
    while (! atomicLoadExplicit(&probe->release_blocker, memory_order_acquire))
    {
        YIELD_THREAD();
    }
}

static void workerMessageBatchCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    worker_message_batch_probe_t      *probe = arg1;
    const worker_message_batch_event_e event = (worker_message_batch_event_e) (uintptr_t) arg2;
    discard                            arg3;

    require(worker->wid == 1, "worker-message batch callback ran on the wrong worker");
    workerMessageBatchRecord(probe, event);
    if (event == kWorkerMessageBatchA)
    {
        require(sendWorkerMessageForceQueueWithCleanup(worker->wid,
                                                       (WorkerMessageCallback) workerMessageBatchCallback,
                                                       NULL,
                                                       probe,
                                                       (void *) (uintptr_t) kWorkerMessageBatchC,
                                                       NULL) == kWorkerMessageSubmitAccepted,
                "recursive worker-message batch callback was not accepted");
    }
    else if (event == kWorkerMessageBatchC)
    {
        atomicStoreExplicit(&probe->complete, true, memory_order_release);
    }
}

static void workerMessageBatchUnrelatedEvent(wevent_t *event)
{
    worker_message_batch_probe_t *probe = event->userdata;
    require(currentThreadIsEventWorkerWID(1), "unrelated batch-fairness event ran on the wrong worker");
    workerMessageBatchRecord(probe, kWorkerMessageBatchUnrelated);
}

static size_t workerMessageBatchFind(const worker_message_batch_probe_t *probe, worker_message_batch_event_e event)
{
    for (size_t i = 0; i < probe->count; ++i)
    {
        if (probe->order[i] == (uint8_t) event)
        {
            return i;
        }
    }
    return SIZE_MAX;
}

void testWorkerMessageBatchOrderingAndFairness(void)
{
    worker_message_batch_probe_t probe;
    memoryZero(&probe, sizeof(probe));
    atomic_init(&probe.release_blocker, false);
    atomic_init(&probe.blocker_entered, false);
    atomic_init(&probe.complete, false);

    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) workerMessageBatchBlocker, NULL, &probe, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "failed to install the worker-message batch blocker");
    waitForAtomicBool(&probe.blocker_entered, "worker-message batch blocker did not start");

    require(sendWorkerMessageForceQueueWithCleanup(1,
                                                   (WorkerMessageCallback) workerMessageBatchCallback,
                                                   NULL,
                                                   &probe,
                                                   (void *) (uintptr_t) kWorkerMessageBatchA,
                                                   NULL) == kWorkerMessageSubmitAccepted,
            "failed to queue worker-message batch A");
    require(sendWorkerMessageForceQueueWithCleanup(1,
                                                   (WorkerMessageCallback) workerMessageBatchCallback,
                                                   NULL,
                                                   &probe,
                                                   (void *) (uintptr_t) kWorkerMessageBatchB,
                                                   NULL) == kWorkerMessageSubmitAccepted,
            "failed to queue worker-message batch B");

    wevent_t unrelated;
    memoryZero(&unrelated, sizeof(unrelated));
    unrelated.cb       = workerMessageBatchUnrelatedEvent;
    unrelated.userdata = &probe;
    require(wloopPostEvent(getWorkerLoop(1), &unrelated), "failed to post the worker-message fairness event");

    atomicStoreExplicit(&probe.release_blocker, true, memory_order_release);
    waitForAtomicBool(&probe.complete, "recursive worker-message batch callback did not complete");

    require(probe.count == ARRAY_SIZE(probe.order), "worker-message batch fixture lost or duplicated a callback");
    const size_t a               = workerMessageBatchFind(&probe, kWorkerMessageBatchA);
    const size_t b               = workerMessageBatchFind(&probe, kWorkerMessageBatchB);
    const size_t c               = workerMessageBatchFind(&probe, kWorkerMessageBatchC);
    const size_t unrelated_index = workerMessageBatchFind(&probe, kWorkerMessageBatchUnrelated);
    require(a < b && b < c, "recursive worker-message FIFO ordering was not preserved");
    require(unrelated_index < c,
            "a sustained worker-message drain did not yield to the unrelated custom event before recursive work");
}

enum
{
    kWorkerMessageFullBatchRecords = kWorkerMessageDrainBatchSize * 2U + 7U,
};

typedef struct worker_message_full_batch_probe_s
{
    atomic_bool release_blocker;
    atomic_bool blocker_entered;
    atomic_bool complete;
    atomic_bool order_failed;
    atomic_uint callbacks;
    atomic_uint next_sequence;
    atomic_uint unrelated_after;
    uint32_t    total;
} worker_message_full_batch_probe_t;

static void workerMessageFullBatchBarrier(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    atomic_bool *complete = arg1;
    discard      arg2;
    discard      arg3;

    require(worker->wid == 1, "worker-message full-batch barrier ran on the wrong worker");
    atomicStoreExplicit(complete, true, memory_order_release);
}

static void workerMessageWaitForTargetDrain(void)
{
    atomic_bool complete;
    atomic_init(&complete, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) workerMessageFullBatchBarrier, NULL, &complete, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "failed to queue the worker-message full-batch barrier");
    waitForAtomicBool(&complete, "worker-message full-batch barrier did not run");
}

static void workerMessageFullBatchBlocker(wevent_t *event)
{
    worker_message_full_batch_probe_t *probe = event->userdata;

    require(currentThreadIsEventWorkerWID(1), "worker-message full-batch blocker ran on the wrong worker");
    atomicStoreExplicit(&probe->blocker_entered, true, memory_order_release);
    while (! atomicLoadExplicit(&probe->release_blocker, memory_order_acquire))
    {
        YIELD_THREAD();
    }
}

static void workerMessageFullBatchCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    worker_message_full_batch_probe_t *probe    = arg1;
    const uint32_t                     sequence = (uint32_t) (uintptr_t) arg2;
    discard                            arg3;

    require(worker->wid == 1, "worker-message full-batch callback ran on the wrong worker");
    const uint32_t expected = atomicAddExplicit(&probe->next_sequence, 1, memory_order_relaxed);
    if (expected != sequence)
    {
        atomicStoreExplicit(&probe->order_failed, true, memory_order_release);
    }
    const uint32_t callbacks = atomicAddExplicit(&probe->callbacks, 1, memory_order_acq_rel) + 1U;
    if (callbacks == probe->total)
    {
        atomicStoreExplicit(&probe->complete, true, memory_order_release);
    }
}

static void workerMessageFullBatchUnrelatedEvent(wevent_t *event)
{
    worker_message_full_batch_probe_t *probe = event->userdata;
    require(currentThreadIsEventWorkerWID(1), "worker-message full-batch unrelated event ran on the wrong worker");
    atomicStoreExplicit(
        &probe->unrelated_after, atomicLoadExplicit(&probe->callbacks, memory_order_acquire), memory_order_release);
}

static void workerMessageFullBatchPrepare(worker_message_full_batch_probe_t *probe)
{
    memoryZero(probe, sizeof(*probe));
    atomic_init(&probe->release_blocker, false);
    atomic_init(&probe->blocker_entered, false);
    atomic_init(&probe->complete, false);
    atomic_init(&probe->order_failed, false);
    atomic_init(&probe->callbacks, 0);
    atomic_init(&probe->next_sequence, 0);
    atomic_init(&probe->unrelated_after, UINT_MAX);
    probe->total = kWorkerMessageFullBatchRecords;

    wevent_t blocker;
    memoryZero(&blocker, sizeof(blocker));
    blocker.cb       = workerMessageFullBatchBlocker;
    blocker.userdata = probe;
    require(wloopPostEvent(getWorkerLoop(1), &blocker), "failed to queue the worker-message full-batch blocker");
    waitForAtomicBool(&probe->blocker_entered, "worker-message full-batch blocker did not start");

    for (uint32_t sequence = 0; sequence < probe->total; ++sequence)
    {
        require(sendWorkerMessageForceQueueWithCleanup(1,
                                                       (WorkerMessageCallback) workerMessageFullBatchCallback,
                                                       NULL,
                                                       probe,
                                                       (void *) (uintptr_t) sequence,
                                                       NULL) == kWorkerMessageSubmitAccepted,
                "failed to queue a worker-message full-batch record");
    }
}

void testWorkerMessageFullBatchFifoAndFairness(void)
{
    workerMessageWaitForTargetDrain();

    worker_message_full_batch_probe_t probe;
    workerMessageFullBatchPrepare(&probe);

    wevent_t unrelated;
    memoryZero(&unrelated, sizeof(unrelated));
    unrelated.cb       = workerMessageFullBatchUnrelatedEvent;
    unrelated.userdata = &probe;
    require(wloopPostEvent(getWorkerLoop(1), &unrelated), "failed to post full-batch unrelated event");

    atomicStoreExplicit(&probe.release_blocker, true, memory_order_release);
    waitForAtomicBool(&probe.complete, "worker-message full-batch records did not complete");

    require(! atomicLoadExplicit(&probe.order_failed, memory_order_acquire),
            "worker-message FIFO order changed across a full drain batch boundary");
    require(atomicLoadExplicit(&probe.callbacks, memory_order_acquire) == probe.total,
            "worker-message full-batch fixture lost or duplicated a record");
    const uint32_t unrelated_after = atomicLoadExplicit(&probe.unrelated_after, memory_order_acquire);
    require(unrelated_after >= kWorkerMessageDrainBatchSize && unrelated_after < probe.total,
            "an unrelated event did not run between full worker-message drain batches");
}

#ifdef WW_WORKER_MESSAGE_LINK_WRAP
void testWorkerMessageHardSuccessorWakeFallback(void)
{
    workerMessageWaitForTargetDrain();

    worker_message_full_batch_probe_t probe;
    workerMessageFullBatchPrepare(&probe);

    /* The blocker already owns the current drain root. Subsequent queue records
     * therefore need a successor wake; force that publication to fail and
     * prove the admitted root synchronously settles every remaining record. */
    atomicStoreExplicit(&g_fail_wakeup_post, true, memory_order_release);
    atomicStoreExplicit(&probe.release_blocker, true, memory_order_release);
    waitForAtomicBool(&probe.complete, "hard successor-wake fallback did not settle all accepted messages");
    atomicStoreExplicit(&g_fail_wakeup_post, false, memory_order_release);

    require(! atomicLoadExplicit(&probe.order_failed, memory_order_acquire),
            "hard successor-wake fallback changed worker-message FIFO order");
    require(atomicLoadExplicit(&probe.callbacks, memory_order_acquire) == probe.total,
            "hard successor-wake fallback lost or duplicated an accepted record");
}
#endif

#if defined(HAS_UNIX_FORK)
typedef struct local_batch_cleanup_probe_s
{
    worker_t    *worker;
    unsigned int stopper_runs;
    unsigned int victim_runs;
    unsigned int victim_cleanups;
    unsigned int nested_runs;
    unsigned int nested_cleanups;
    bool         cleanup_saw_normal_authority;
} local_batch_cleanup_probe_t;

static void localBatchNestedCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    local_batch_cleanup_probe_t *probe = arg1;
    discard                      worker;
    discard                      arg2;
    discard                      arg3;
    ++probe->nested_runs;
}

static void localBatchNestedCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    local_batch_cleanup_probe_t *probe = arg1;
    discard                      arg2;
    discard                      arg3;
    require(reason == kWorkerMessageCancelAdmissionClosed,
            "local-batch cleanup re-entry used the wrong cancellation reason");
    ++probe->nested_cleanups;
}

static void localBatchStopper(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    local_batch_cleanup_probe_t *probe = arg1;
    discard                      arg2;
    discard                      arg3;

    ++probe->stopper_runs;
    workerMessagesCloseAdmission(worker);
    require(wloopCloseNormalAdmission(worker->loop), "local-batch stopper could not close normal admission");
}

static void localBatchVictim(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    local_batch_cleanup_probe_t *probe = arg1;
    discard                      worker;
    discard                      arg2;
    discard                      arg3;
    ++probe->victim_runs;
}

static void localBatchVictimCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    local_batch_cleanup_probe_t *probe = arg1;
    discard                      arg2;
    discard                      arg3;

    require(reason == kWorkerMessageCancelQuiesced, "local-batch victim used the wrong cancellation reason");
    ++probe->victim_cleanups;
    probe->cleanup_saw_normal_authority = wloopCurrentThreadInNormalCallback(probe->worker->loop);
    sendWorkerMessageWithCleanup(probe->worker->wid,
                                 (WorkerMessageCallback) localBatchNestedCallback,
                                 localBatchNestedCleanup,
                                 probe,
                                 NULL,
                                 NULL);
}

static void testLocalBatchCleanupCannotReadmitMessages(void)
{
    local_batch_cleanup_probe_t probe = {.worker = getWorker(0)};

    require(sendWorkerMessageForceQueueWithCleanup(
                0, (WorkerMessageCallback) localBatchStopper, NULL, &probe, NULL, NULL) == kWorkerMessageSubmitAccepted,
            "failed to queue the local-batch stopper");
    require(sendWorkerMessageForceQueueWithCleanup(
                0, (WorkerMessageCallback) localBatchVictim, localBatchVictimCleanup, &probe, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "failed to queue the local-batch victim");

    discard wloopProcessEvents(probe.worker->loop, 0);
    require(probe.stopper_runs == 1, "local-batch stopper did not run exactly once");
    require(probe.victim_runs == 0, "local-batch victim ran after quiescence");
    require(probe.victim_cleanups == 1, "local-batch victim cleanup did not run exactly once");
    require(! probe.cleanup_saw_normal_authority, "local-batch cancellation inherited normal callback authority");
    require(probe.nested_runs == 0, "local-batch cancellation re-admitted a same-worker callback inline");
    require(probe.nested_cleanups == 1, "local-batch cancellation re-entry was not refused and cleaned exactly once");
}

void testLocalBatchCleanupCannotReadmitInIsolatedProcess(void)
{
    pid_t pid = fork();
    require(pid >= 0, "fork failed for local-batch cancellation authority case");
    if (pid == 0)
    {
        initTestGlobalState();
        testLocalBatchCleanupCannotReadmitMessages();
        shutdownTestGlobalState();
        _Exit(0);
    }

    int status = 0;
    require(waitpid(pid, &status, 0) == pid, "waitpid failed for local-batch cancellation authority case");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "local-batch cancellation authority child failed");
}

enum
{
    kLocalBatchPositionRecords = 16,
};

typedef struct local_batch_position_probe_s
{
    worker_t    *worker;
    uint32_t     stopper_position;
    unsigned int started;
    unsigned int cleanups;
} local_batch_position_probe_t;

static void localBatchPositionCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    local_batch_position_probe_t *probe    = arg1;
    const uint32_t                position = (uint32_t) (uintptr_t) arg2;
    discard                       arg3;

    require(worker == probe->worker, "local-batch position callback ran on the wrong worker");
    ++probe->started;
    if (position == probe->stopper_position)
    {
        workerMessagesCloseAdmission(worker);
        require(wloopCloseNormalAdmission(worker->loop), "local-batch position stopper could not close admission");
    }
}

static void localBatchPositionCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    local_batch_position_probe_t *probe = arg1;
    discard                       arg2;
    discard                       arg3;

    require(reason == kWorkerMessageCancelQuiesced, "local-batch position cleanup used the wrong reason");
    ++probe->cleanups;
}

static void testLocalBatchQuiescencePosition(uint32_t stopper_position)
{
    local_batch_position_probe_t probe = {
        .worker           = getWorker(0),
        .stopper_position = stopper_position,
    };
    require(stopper_position < kLocalBatchPositionRecords, "invalid local-batch stopper position");

    for (uint32_t position = 0; position < kLocalBatchPositionRecords; ++position)
    {
        require(sendWorkerMessageForceQueueWithCleanup(0,
                                                       (WorkerMessageCallback) localBatchPositionCallback,
                                                       localBatchPositionCleanup,
                                                       &probe,
                                                       (void *) (uintptr_t) position,
                                                       NULL) == kWorkerMessageSubmitAccepted,
                "failed to queue a local-batch position record");
    }
    discard wloopProcessEvents(probe.worker->loop, 0);

    require(probe.started == stopper_position + 1U,
            "local-batch quiescence started a callback after its configured closure position");
    require(probe.cleanups == kLocalBatchPositionRecords - probe.started,
            "local-batch quiescence did not clean the exact unstarted suffix");
}

void testLocalBatchQuiescencePositionsInIsolatedProcess(void)
{
    const uint32_t positions[] = {0, kLocalBatchPositionRecords / 2U, kLocalBatchPositionRecords - 1U};
    for (uint32_t index = 0; index < ARRAY_SIZE(positions); ++index)
    {
        pid_t pid = fork();
        require(pid >= 0, "fork failed for local-batch position case");
        if (pid == 0)
        {
            initTestGlobalState();
            testLocalBatchQuiescencePosition(positions[index]);
            shutdownTestGlobalState();
            _Exit(0);
        }

        int status = 0;
        require(waitpid(pid, &status, 0) == pid, "waitpid failed for local-batch position case");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "local-batch position child failed");
    }
}

typedef enum pending_cleanup_kind_e
{
    kPendingCleanupQueued,
    kPendingCleanupTimed,
} pending_cleanup_kind_e;

typedef struct pending_cleanup_reentry_probe_s
{
    worker_t    *worker;
    unsigned int primary_cleanups;
    unsigned int nested_callbacks;
    unsigned int nested_cleanups;
    bool         cleanup_saw_normal_authority;
} pending_cleanup_reentry_probe_t;

static void pendingCleanupNestedCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    pending_cleanup_reentry_probe_t *probe = arg1;
    discard                          worker;
    discard                          arg2;
    discard                          arg3;
    ++probe->nested_callbacks;
}

static void pendingCleanupNestedCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    pending_cleanup_reentry_probe_t *probe = arg1;
    discard                          arg2;
    discard                          arg3;

    require(reason == kWorkerMessageCancelAdmissionClosed,
            "pending cleanup re-entry used the wrong immediate-refusal reason");
    ++probe->nested_cleanups;
}

static void pendingCleanupUnexpectedCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg1;
    discard arg2;
    discard arg3;
    require(false, "pending worker-message cleanup fixture unexpectedly ran a callback");
}

static void pendingCleanupReentry(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    pending_cleanup_reentry_probe_t *probe = arg1;
    discard                          arg2;
    discard                          arg3;

    require(reason == kWorkerMessageCancelQuiesced, "pending cleanup fixture used the wrong cancellation reason");
    ++probe->primary_cleanups;
    probe->cleanup_saw_normal_authority = wloopCurrentThreadInNormalCallback(probe->worker->loop);
    sendWorkerMessageWithCleanup(probe->worker->wid,
                                 (WorkerMessageCallback) pendingCleanupNestedCallback,
                                 pendingCleanupNestedCleanup,
                                 probe,
                                 NULL,
                                 NULL);
}

static void testPendingCleanupReentry(pending_cleanup_kind_e kind)
{
    pending_cleanup_reentry_probe_t      probe = {.worker = getWorker(0)};
    const worker_message_submit_result_e result =
        kind == kPendingCleanupTimed
            ? sendWorkerMessageTimedWithCleanup(0,
                                                (WorkerMessageCallback) pendingCleanupUnexpectedCallback,
                                                pendingCleanupReentry,
                                                60000,
                                                &probe,
                                                NULL,
                                                NULL)
            : sendWorkerMessageForceQueueWithCleanup(0,
                                                     (WorkerMessageCallback) pendingCleanupUnexpectedCallback,
                                                     pendingCleanupReentry,
                                                     &probe,
                                                     NULL,
                                                     NULL);
    require(result == kWorkerMessageSubmitAccepted, "pending cleanup fixture was not accepted");

    workerMessagesCloseAdmission(probe.worker);
    workerMessagesCleanupPending(probe.worker);
    require(probe.primary_cleanups == 1, "pending cleanup did not run exactly once");
    require(! probe.cleanup_saw_normal_authority, "pending cleanup inherited normal callback authority");
    require(probe.nested_callbacks == 0, "pending cleanup re-entry unexpectedly executed inline");
    require(probe.nested_cleanups == 1, "pending cleanup re-entry did not settle exactly once");
}

void testPendingCleanupReentryInIsolatedProcess(void)
{
    const pending_cleanup_kind_e kinds[] = {kPendingCleanupQueued, kPendingCleanupTimed};
    for (uint32_t index = 0; index < ARRAY_SIZE(kinds); ++index)
    {
        pid_t pid = fork();
        require(pid >= 0, "fork failed for pending-cleanup re-entry case");
        if (pid == 0)
        {
            initTestGlobalState();
            testPendingCleanupReentry(kinds[index]);
            shutdownTestGlobalState();
            _Exit(0);
        }

        int status = 0;
        require(waitpid(pid, &status, 0) == pid, "waitpid failed for pending-cleanup re-entry case");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "pending-cleanup re-entry child failed");
    }
}

typedef struct foreign_delayed_probe_s
{
    atomic_int callbacks;
    atomic_int cleanups;
    atomic_int cancellation_reason;
    atomic_int submit_result;
} foreign_delayed_probe_t;

static void foreignDelayedCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    foreign_delayed_probe_t *probe = arg1;
    discard                  arg2;
    discard                  arg3;

    require(worker->wid == 0, "foreign delayed callback ran on the wrong worker");
    atomicAddExplicit(&probe->callbacks, 1, memory_order_relaxed);
}

static void foreignDelayedCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    foreign_delayed_probe_t *probe = arg1;
    discard                  arg2;
    discard                  arg3;

    atomicStoreExplicit(&probe->cancellation_reason, (int) reason, memory_order_release);
    atomicAddExplicit(&probe->cleanups, 1, memory_order_relaxed);
}

static WTHREAD_ROUTINE(foreignDelayedPoster)
{
    foreign_delayed_probe_t *probe = userdata;
    require(getWID() == kInvalidWID, "foreign delayed poster inherited an event-worker identity");
    atomicStoreExplicit(
        &probe->submit_result,
        (int) sendWorkerMessageTimedWithCleanup(
            0, (WorkerMessageCallback) foreignDelayedCallback, foreignDelayedCleanup, 60000, probe, NULL, NULL),
        memory_order_release);
    return 0;
}

static void testForeignDelayedCancellation(bool arm_timer_first)
{
    foreign_delayed_probe_t probe;
    memoryZero(&probe, sizeof(probe));
    atomic_init(&probe.callbacks, 0);
    atomic_init(&probe.cleanups, 0);
    atomic_init(&probe.cancellation_reason, -1);
    atomic_init(&probe.submit_result, -1);

    worker_t      *worker        = getWorker(0);
    wloop_t       *loop          = worker->loop;
    const uint32_t timers_before = loop->ntimers;
    wthread_t      poster;
    require(threadCreate(&poster, foreignDelayedPoster, &probe) == kWThreadErrorNone,
            "failed to create foreign delayed poster");
    require(threadJoin(poster) == 0, "failed to join foreign delayed poster");
    require(atomicLoadExplicit(&probe.submit_result, memory_order_acquire) == kWorkerMessageSubmitAccepted,
            "foreign delayed setup wrapper was not accepted");

    if (arm_timer_first)
    {
        for (uint32_t attempt = 0; attempt < 5000U && loop->ntimers == timers_before; ++attempt)
        {
            discard wloopProcessEvents(loop, 0);
            wwSleepMS(1);
        }
        require(loop->ntimers > timers_before, "foreign delayed setup wrapper did not arm its timer");
    }

    workerMessagesCloseAdmission(worker);
    workerMessagesCleanupPending(worker);
    require(atomicLoadRelaxed(&probe.callbacks) == 0, "canceled foreign delayed task ran its callback");
    require(atomicLoadRelaxed(&probe.cleanups) == 1, "canceled foreign delayed task did not clean exactly once");
    require(atomicLoadExplicit(&probe.cancellation_reason, memory_order_acquire) == kWorkerMessageCancelQuiesced,
            "foreign delayed cancellation used the wrong reason");
}

void testForeignDelayedCancellationInIsolatedProcess(void)
{
    for (uint32_t arm_timer_first = 0; arm_timer_first < 2; ++arm_timer_first)
    {
        pid_t pid = fork();
        require(pid >= 0, "fork failed for foreign delayed cancellation case");
        if (pid == 0)
        {
            initTestGlobalState();
            testForeignDelayedCancellation(arm_timer_first != 0);
            shutdownTestGlobalState();
            _Exit(0);
        }

        int status = 0;
        require(waitpid(pid, &status, 0) == pid, "waitpid failed for foreign delayed cancellation case");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "foreign delayed cancellation child failed");
    }
}

typedef struct delayed_pattern_probe_s
{
    atomic_int callbacks;
    atomic_int cleanups;
    atomic_int quiesced_cleanups;
} delayed_pattern_probe_t;

static void delayedPatternCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    delayed_pattern_probe_t *probe = arg1;
    discard                  arg2;
    discard                  arg3;

    require(worker->wid == 0, "delayed pattern callback ran on the wrong worker");
    atomicAddExplicit(&probe->callbacks, 1, memory_order_relaxed);
}

static void delayedPatternCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    delayed_pattern_probe_t *probe = arg1;
    discard                  arg2;
    discard                  arg3;

    if (reason == kWorkerMessageCancelQuiesced)
    {
        atomicAddExplicit(&probe->quiesced_cleanups, 1, memory_order_relaxed);
    }
    atomicAddExplicit(&probe->cleanups, 1, memory_order_relaxed);
}

static void waitForDelayedPatternCallbacks(wloop_t *loop, const delayed_pattern_probe_t *probe, int expected,
                                           const char *message)
{
    for (uint32_t attempt = 0; attempt < 5000U && atomicLoadRelaxed(&probe->callbacks) < expected; ++attempt)
    {
        wwSleepMS(1);
        discard wloopProcessEvents(loop, 0);
    }
    require(atomicLoadRelaxed(&probe->callbacks) == expected, message);
}

static uint32_t delayedPatternDeadline(uint32_t index)
{
    switch (index % 4U)
    {
    case 0:
        return 5; /* equal deadlines */
    case 1:
        return index / 4U % 16U + 1U; /* increasing */
    case 2:
        return 16U - (index / 4U % 16U); /* decreasing */
    default:
        return (index * 7U) % 16U + 1U; /* mixed */
    }
}

static void testDelayedPatternCompletionAndCancellation(void)
{
    enum
    {
        kPatternRecords = 256,
        kMixedImmediate = 128,
        kMixedDelayed   = 128,
    };
    delayed_pattern_probe_t probe;
    memoryZero(&probe, sizeof(probe));
    atomic_init(&probe.callbacks, 0);
    atomic_init(&probe.cleanups, 0);
    atomic_init(&probe.quiesced_cleanups, 0);
    wloop_t *loop = getWorkerLoop(0);

    for (uint32_t index = 0; index < kPatternRecords; ++index)
    {
        require(sendWorkerMessageTimedWithCleanup(0,
                                                  (WorkerMessageCallback) delayedPatternCallback,
                                                  delayedPatternCleanup,
                                                  delayedPatternDeadline(index),
                                                  &probe,
                                                  NULL,
                                                  NULL) == kWorkerMessageSubmitAccepted,
                "failed to arm a delayed pattern record");
    }
    waitForDelayedPatternCallbacks(
        loop, &probe, kPatternRecords, "delayed equal/increasing/decreasing/mixed records did not all complete");
    require(atomicLoadRelaxed(&probe.cleanups) == 0, "completed delayed pattern record unexpectedly ran cleanup");

    for (uint32_t index = 0; index < kMixedImmediate + kMixedDelayed; ++index)
    {
        const uint32_t delay_ms = index < kMixedImmediate ? 1U : 60000U;
        require(sendWorkerMessageTimedWithCleanup(0,
                                                  (WorkerMessageCallback) delayedPatternCallback,
                                                  delayedPatternCleanup,
                                                  delay_ms,
                                                  &probe,
                                                  NULL,
                                                  NULL) == kWorkerMessageSubmitAccepted,
                "failed to arm a mixed completion/cancellation record");
    }
    waitForDelayedPatternCallbacks(loop,
                                   &probe,
                                   kPatternRecords + kMixedImmediate,
                                   "mixed immediate delayed records did not complete before quiescence");

    workerMessagesCloseAdmission(getWorker(0));
    workerMessagesCleanupPending(getWorker(0));
    require(atomicLoadRelaxed(&probe.callbacks) == kPatternRecords + kMixedImmediate,
            "mixed delayed cancellation ran an unexpected callback");
    require(atomicLoadRelaxed(&probe.cleanups) == kMixedDelayed,
            "mixed delayed cancellation did not clean every uncompleted record");
    require(atomicLoadRelaxed(&probe.quiesced_cleanups) == kMixedDelayed,
            "mixed delayed cancellation did not report the quiesced reason");
}

void testDelayedPatternCompletionAndCancellationInIsolatedProcess(void)
{
    pid_t pid = fork();
    require(pid >= 0, "fork failed for delayed pattern completion/cancellation case");
    if (pid == 0)
    {
        initTestGlobalState();
        testDelayedPatternCompletionAndCancellation();
        shutdownTestGlobalState();
        _Exit(0);
    }

    int status = 0;
    require(waitpid(pid, &status, 0) == pid, "waitpid failed for delayed pattern completion/cancellation case");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "delayed pattern completion/cancellation child failed");
}
#endif

void testAdmissionOpenIsOneWayAndChecked(void)
{
    worker_t incomplete;
    memoryZero(&incomplete, sizeof(incomplete));
    incomplete.wid            = 0;
    incomplete.has_event_loop = true;
    mutexInit(&incomplete.control_mutex);
    atomic_init(&incomplete.lifecycle, (w_atomic_int_value_t) kWorkerLifecycleInitialized);
    atomic_init(&incomplete.resources_destroyed, false);
    atomic_init(&incomplete.message_admission_open, false);

    require(! workerMessagesOpenAdmission(&incomplete), "message admission opened before loop/queue readiness");
    require(! atomicLoadRelaxed(&incomplete.message_admission_open), "failed open changed the admission gate");
    incomplete.has_event_loop = false;
    require(! workerMessagesOpenAdmission(&incomplete), "non-event worker admission was accepted");
    mutexDestroy(&incomplete.control_mutex);

    require(! workerMessagesOpenAdmission(getWorker(0)), "duplicate message-admission open was accepted");
}

static int probeRuns(void)
{
    return (int) atomicLoadExplicit(&g_probe.ran, memory_order_relaxed);
}

static int probeCleanups(void)
{
    return (int) atomicLoadExplicit(&g_probe.cleaned, memory_order_relaxed);
}

void testOwningWorkerOutsideCallbackQueues(void)
{
    probeReset();
    sendWorkerMessageWithCleanup(0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    require(probeRuns() == 0, "same-worker message outside a callback executed inline");
    require(probeCleanups() == 0, "queued same-worker message ran cleanup before settlement");
}

void testOtherEventWorkerQueues(void)
{
    probeReset();
    sendWorkerMessageWithCleanup(1, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    require(probeRuns() == 0, "message aimed at worker 1 executed inline on worker 0");
    require(probeCleanups() == 0, "queued message ran its cleanup callback");
}

static WTHREAD_ROUTINE(unregisteredPosterRoutine)
{
    discard userdata;

    require(getWID() == kInvalidWID, "poster thread was not unregistered");

    // Same target as the inline case above: an unregistered caller must never
    // take the inline branch, even for worker 0.
    sendWorkerMessageWithCleanup(0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    return 0;
}

void testUnregisteredThreadQueues(void)
{
    probeReset();

    wthread_t thread;
    require(threadCreate(&thread, unregisteredPosterRoutine, NULL) == kWThreadErrorNone,
            "failed to spawn unregistered poster thread");
    require(threadJoin(thread) == 0, "failed to join unregistered poster thread");

    require(probeRuns() == 0, "unregistered thread executed a worker message inline");
    require(probeCleanups() == 0, "queued message from an unregistered thread ran its cleanup");
}

void testOutOfRangeCallerQueues(void)
{
    probeReset();

    testWorkerBindWID(getTotalWorkersCount());
    sendWorkerMessageWithCleanup(0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    testWorkerBindWID(0);

    require(probeRuns() == 0, "out-of-range identity executed a worker message inline");
    require(probeCleanups() == 0, "message queued from lwIP ran its cleanup");
}

void testInvalidTargetsCleanUpExactlyOnce(void)
{
    const wid_t unregistered_wid = getTotalWorkersCount();

    const wid_t bad_targets[] = {kInvalidWID, unregistered_wid};

    for (size_t i = 0; i < ARRAY_SIZE(bad_targets); ++i)
    {
        probeReset();
        require(! sendWorkerMessageForceQueueWithCleanup(
                    bad_targets[i], (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL),
                "posting to an undeliverable target reported success");
        require(probeRuns() == 0, "undeliverable target still ran the callback");
        require(probeCleanups() == 1, "undeliverable target did not run cleanup exactly once");

        probeReset();
        sendWorkerMessageWithCleanup(
            bad_targets[i], (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
        require(probeRuns() == 0, "undeliverable target still ran the callback");
        require(probeCleanups() == 1, "undeliverable target did not run cleanup exactly once");

        probeReset();
        const bool accepted = sendWorkerMessageTimedWithCleanup(
            bad_targets[i], (WorkerMessageCallback) probeCallback, probeCleanup, 25, NULL, NULL, NULL);
        require(! accepted, "posting a timed message to an undeliverable target reported success");
        require(probeRuns() == 0, "undeliverable timed target still ran the callback");
        require(probeCleanups() == 1, "undeliverable timed target did not run cleanup exactly once");
    }
}
