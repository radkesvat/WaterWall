/*
 * Focused coverage for the checked worker-context helpers and for the
 * worker-message bridge that unregistered, foreign and pseudo-worker threads
 * depend on.
 *
 * The rule under test: nothing except the actual owning event worker may reach
 * worker-local state, and nothing ever silently falls back to worker 0.
 */

#include "ev_memory.h"
#include "global_state.h"
#include "wloop_internal.h"
#include "worker.h"
#include "worker_message_batch.h"
#include "worker_messages.h"
#include "wwapi.h"

#if defined(__unix__) || defined(__APPLE__) || defined(UNIX)
#include <sys/wait.h>
#include <unistd.h>
#define HAS_UNIX_FORK 1
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static const ww_lifecycle_context_t *testShutdownContext(void)
{
    static const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleProcessShutdown,
        .close_policy = kWwLifecycleCloseGraceful,
    };
    return &context;
}

static void teardownCurrentWorker(worker_t *worker)
{
    require(workerInstallApplicationQuiesceRequest(worker, testShutdownContext()) != kWorkerQuiesceRequestUnavailable,
            "failed to install worker-0 application quiesce request");
    workerPerformQuiesce(worker, testShutdownContext());
    require(workerRequestDrain(worker), "failed to request current-worker drain");
    workerPerformDrain(worker, testShutdownContext());
    require(workerRequestTeardown(worker), "failed to request current-worker teardown");
    workerPerformTeardown(worker);
}

static void initTestGlobalState(void)
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

static void shutdownTestGlobalState(void)
{
    for (unsigned int wid = 1; wid < getWorkersCount(); ++wid)
    {
        require(workerExitJoin(getWorker(wid)), "failed to stop a test worker");
    }

    /*
     * Worker 0 is bound to this test thread and is therefore never joined.
     * Release its event-loop resources explicitly so the c-ares channel is
     * cleaned before destroyGlobalState() tears down the global library.
     * The lwIP pseudo-worker has no loop, but still owns pools and a message
     * queue that follow the same worker-resource lifetime contract.
     */
    if (! atomicLoadExplicit(&getWorker(0)->resources_destroyed, memory_order_relaxed))
    {
        teardownCurrentWorker(getWorker(0));
    }
    workerDestroyPseudoWorkerResources(getWorker(getTotalWorkersCount() - 1));
    destroyGlobalState();
}

static void testWorkerMessageConstructionTransactional(void)
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

// ---------------------------------------------------------------------------
// Checked accessors
// ---------------------------------------------------------------------------

static void testAccessorsOnOwningWorker(void)
{
    require(currentThreadIsEventWorkerWID(0), "main thread is not bound to event worker 0");

    require(getCurrentEventWorker() == getWorker(0), "getCurrentEventWorker() did not return worker 0");
    require(tryGetCurrentEventWorker() == getWorker(0), "tryGetCurrentEventWorker() did not return worker 0");
    require(getCurrentEventWorkerWID() == 0, "getCurrentEventWorkerWID() did not return 0");
    require(getCurrentEventWorkerBufferPool() == getWorkerBufferPool(0), "current buffer pool is not worker 0's");
    require(getCurrentEventWorkerContextPool() == getWorkerContextPool(0), "current context pool is not worker 0's");
    require(getCurrentEventWorkerLoop() == getWorkerLoop(0), "current loop is not worker 0's");
    require(getLoopEventWorkerWID(getWorkerLoop(0)) == 0, "getLoopEventWorkerWID() did not resolve worker 0");

    // Another event worker's resources are reachable by explicit id only, and
    // must not be confused with the current worker's.
    require(getWorkerBufferPool(1) != getCurrentEventWorkerBufferPool(),
            "worker 1's pool aliased the current worker's pool");
    require(! currentThreadIsEventWorkerWID(1), "worker 0 claimed to own worker 1");
}

static void testPredicatesRejectUnregisteredAndLwip(void)
{
    const wid_t lwip_wid = getTotalWorkersCount() - 1;

    testWorkerUnbindWID();
    require(tryGetCurrentEventWorker() == NULL, "unregistered thread got an event worker");
    require(! currentThreadIsEventWorker(), "unregistered thread reported event worker role");
    require(! currentThreadIsEventWorkerWID(0), "unregistered thread claimed to own worker 0");

    testWorkerBindWID(lwip_wid);
    require(currentThreadHasRegisteredWID(), "lwIP pseudo-worker is not registered");
    require(! currentThreadIsEventWorker(), "lwIP pseudo-worker reported event worker role");
    require(tryGetCurrentEventWorker() == NULL, "lwIP pseudo-worker got an event worker");
    require(! currentThreadIsEventWorkerWID(0), "lwIP pseudo-worker claimed to own worker 0");
    require(! currentThreadIsEventWorkerWID(lwip_wid), "lwIP pseudo-worker passed an event-worker check");
    require(workerWIDForLog(0) == 0, "workerWIDForLog(0) did not return 0");
    require(workerWIDForLog(1) == 1, "workerWIDForLog(1) did not return 1");
    require(workerWIDForLog(lwip_wid) == (int) lwip_wid, "workerWIDForLog did not preserve lwIP WID numerically");
    require(workerWIDForLog(lwip_wid) != -1, "workerWIDForLog mapped lwIP WID to -1");
    require(workerWIDForLog(kInvalidWID) == -1, "workerWIDForLog(kInvalidWID) did not return -1");

    testWorkerBindWID(0);
}

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

static atomic_int        g_enqueue_pause_stage = ATOMIC_VAR_INIT(-1);
static atomic_int        g_enqueue_pause_wid   = ATOMIC_VAR_INIT(-1);
static atomic_bool       g_force_timed_rearm_refusal;
static atomic_bool       g_enqueue_seam_reached;
static atomic_bool       g_enqueue_seam_release;
static atomic_int        g_enqueue_seam_hits;
static atomic_bool       g_pipe_stop_in_fast_check_seam;
static atomic_uint       g_pipe_init_count;
static atomic_uint       g_pipe_owned_finish_count;
static atomic_uint       g_pipe_borrowed_finish_count;
static atomic_uint       g_pipe_owned_payload_count;
static atomic_uint       g_pipe_borrowed_payload_count;
static _Atomic(line_t *) g_pipe_owned_line;

void        pipeTunnelAfterFastStopCheckTestSeam(tunnel_t *wrapper, line_t *source_line);
static void testPipePublicationIsLinearizedWithPreStop(void);
static void testPipePayloadFinishLateAndRefused(void);
static void waitForAtomicBool(const atomic_bool *value, const char *message);

void pipeTunnelAfterFastStopCheckTestSeam(tunnel_t *wrapper, line_t *source_line)
{
    discard source_line;
    if (atomicExchangeExplicit(&g_pipe_stop_in_fast_check_seam, false, memory_order_acq_rel))
    {
        wrapper->onQuiesceRequest(wrapper, testShutdownContext());
    }
}

static void pipeTestOwnedInit(tunnel_t *t, line_t *line)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe Init ran outside its target worker");
    atomicStoreExplicit(&g_pipe_owned_line, line, memory_order_release);
    atomicAddExplicit(&g_pipe_init_count, 1, memory_order_relaxed);
}

typedef struct pipe_payload_lifetime_s
{
    sbuf_lifetime_t base;
    atomic_uint     releases;
} pipe_payload_lifetime_t;

static void pipePayloadLifetimeRetain(sbuf_lifetime_t *base)
{
    discard base;
    require(false, "pipe payload was unexpectedly cloned");
}

static void pipePayloadLifetimeRelease(sbuf_lifetime_t *base)
{
    pipe_payload_lifetime_t *lifetime = (pipe_payload_lifetime_t *) base;
    atomicAddExplicit(&lifetime->releases, 1, memory_order_relaxed);
}

static sbuf_t *pipeTestPayload(pipe_payload_lifetime_t *lifetime)
{
    *lifetime = (pipe_payload_lifetime_t) {
        .base = {.retain = pipePayloadLifetimeRetain, .release = pipePayloadLifetimeRelease},
    };
    atomic_init(&lifetime->releases, 0);
    sbuf_t *buf = sbufCreate(32);
    require(buf != NULL, "failed to allocate a pipe payload");
    sbufSetLength(buf, 32);
    sbufAttachLifetime(buf, &lifetime->base);
    return buf;
}

static void pipeTestOwnedPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe owned Payload ran outside its target worker");
    atomicAddExplicit(&g_pipe_owned_payload_count, 1, memory_order_relaxed);
    sbufDestroy(buf);
}

static void pipeTestBorrowedPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe borrowed Payload ran outside its owner worker");
    atomicAddExplicit(&g_pipe_borrowed_payload_count, 1, memory_order_relaxed);
    sbufDestroy(buf);
}

typedef struct pipe_down_call_s
{
    tunnel_t                             *wrapper;
    line_t                               *line;
    sbuf_t                               *payload;
    atomic_bool                          *done;
    worker_message_enqueue_test_failure_e failure;
    bool                                  finish;
} pipe_down_call_t;

static void pipeDownCallOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard           arg2;
    discard           arg3;
    pipe_down_call_t *call = arg1;
    require(worker->wid == lineGetWID(call->line), "pipe downstream callback ran on the wrong worker");
#ifdef WW_WORKER_MESSAGE_TEST_SEAM
    if (call->failure != kWorkerMessageEnqueueFailNone)
    {
        workerMessagesEnqueueTestSetFailure(call->failure);
    }
#endif
    if (call->finish)
    {
        call->wrapper->fnFinD(call->wrapper, call->line);
    }
    else
    {
        call->wrapper->fnPayloadD(call->wrapper, call->line, call->payload);
    }
    if (call->done != NULL)
    {
        atomicStoreExplicit(call->done, true, memory_order_release);
    }
}

static void pipeWorkerStopCall(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg3;
    ((tunnel_t *) arg1)->onWorkerStop(arg1, worker->wid, testShutdownContext());
    if (arg2 != NULL)
    {
        atomicStoreExplicit((atomic_bool *) arg2, true, memory_order_release);
    }
}

static void pipeTestOwnedFinish(tunnel_t *t, line_t *line)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe owned Finish ran outside its target worker");
    atomicAddExplicit(&g_pipe_owned_finish_count, 1, memory_order_relaxed);
}

static void pipeTestBorrowedFinish(tunnel_t *t, line_t *line)
{
    discard t;
    require(currentThreadIsEventWorkerWID(lineGetWID(line)), "pipe borrowed Finish ran outside its owner worker");
    atomicAddExplicit(&g_pipe_borrowed_finish_count, 1, memory_order_relaxed);
}

#ifdef WW_WORKER_MESSAGE_LINK_WRAP
static atomic_bool g_fail_wakeup_post;
static atomic_uint g_pipe_shutdown_requests;

bool __real_wloopPostEvent(wloop_t *loop, wevent_t *event);
bool __wrap_wloopPostEvent(wloop_t *loop, wevent_t *event);
bool __wrap_signalmanagerRequestShutdownPreservingAcceptedStatus(int exit_code);

bool __wrap_signalmanagerRequestShutdownPreservingAcceptedStatus(int exit_code)
{
    require(exit_code == 1, "pipe refusal requested the wrong shutdown status");
    atomicAddExplicit(&g_pipe_shutdown_requests, 1, memory_order_relaxed);
    return true;
}

bool __wrap_wloopPostEvent(wloop_t *loop, wevent_t *event)
{
    if (atomicLoadExplicit(&g_fail_wakeup_post, memory_order_acquire))
    {
        return false;
    }
    return __real_wloopPostEvent(loop, event);
}
#endif

void workerMessageEnqueueTestSeam(worker_t *worker, worker_message_enqueue_test_stage_e stage)
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

static void testTransactionalEnqueueFailureStages(void)
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

typedef enum
{
    kRacePostNormal = 0,
    kRacePostWithCleanup,
    kRacePostRetainOnRefusal,
    kRacePostTimed
} race_post_kind_e;

typedef struct worker_message_race_s
{
    atomic_int       delivered;
    atomic_int       cleaned;
    atomic_int       returned;
    atomic_bool      accepted;
    atomic_bool      poster_done;
    atomic_bool      teardown_done;
    wid_t            target_wid;
    race_post_kind_e kind;
} worker_message_race_t;

typedef struct worker_loop_blocker_s
{
    atomic_bool entered;
    atomic_bool release;
    atomic_int  nested_runs;
    atomic_int  nested_cleanups;
    bool        run_nested_after_close;
} worker_loop_blocker_t;

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

static void workerLoopBlockerCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
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

static void raceCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    worker_message_race_t *race = arg1;
    discard                arg2;
    discard                arg3;
    require(worker->wid == race->target_wid, "raced message ran on the wrong worker");
    atomicAddExplicit(&race->delivered, 1, memory_order_relaxed);
}

static void raceCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                reason;
    worker_message_race_t *race = arg1;
    discard                arg2;
    discard                arg3;
    atomicAddExplicit(&race->cleaned, 1, memory_order_relaxed);
}

static WTHREAD_ROUTINE(racePosterRoutine)
{
    worker_message_race_t *race = userdata;
    bool                   accepted;

    if (race->kind == kRacePostNormal)
    {
        sendWorkerMessageForceQueueBestEffort(race->target_wid, (WorkerMessageCallback) raceCallback, race, NULL, NULL);
        accepted = false; /* The legacy fire-and-forget form has no result. */
    }
    else if (race->kind == kRacePostRetainOnRefusal)
    {
        accepted = sendWorkerMessageForceQueueRetainOnRefusal(
                       race->target_wid, (WorkerMessageCallback) raceCallback, raceCleanup, race, NULL, NULL) ==
                   kWorkerMessageSubmitAccepted;
        if (! accepted)
        {
            atomicAddExplicit(&race->returned, 1, memory_order_relaxed);
        }
    }
    else if (race->kind == kRacePostTimed)
    {
        accepted = sendWorkerMessageTimedWithCleanup(
                       race->target_wid, (WorkerMessageCallback) raceCallback, raceCleanup, 25U, race, NULL, NULL) ==
                   kWorkerMessageSubmitAccepted;
    }
    else
    {
        accepted = sendWorkerMessageForceQueueWithCleanup(
                       race->target_wid, (WorkerMessageCallback) raceCallback, raceCleanup, race, NULL, NULL) ==
                   kWorkerMessageSubmitAccepted;
    }

    atomicStoreExplicit(&race->accepted, accepted, memory_order_release);
    atomicStoreExplicit(&race->poster_done, true, memory_order_release);
    return 0;
}

static WTHREAD_ROUTINE(raceTeardownRoutine)
{
    worker_message_race_t *race = userdata;
    require(workerExitJoin(getWorker(race->target_wid)), "raced worker teardown failed");
    atomicStoreExplicit(&race->teardown_done, true, memory_order_release);
    return 0;
}

static void waitForAtomicBool(const atomic_bool *value, const char *message)
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

static void initializeRace(worker_message_race_t *race, wid_t wid, race_post_kind_e kind)
{
    memoryZero(race, sizeof(*race));
    atomic_init(&race->delivered, 0);
    atomic_init(&race->cleaned, 0);
    atomic_init(&race->returned, 0);
    atomic_init(&race->accepted, false);
    atomic_init(&race->poster_done, false);
    atomic_init(&race->teardown_done, false);
    race->target_wid = wid;
    race->kind       = kind;
}

static void configureRaceSeam(wid_t wid, worker_message_enqueue_test_stage_e stage)
{
    atomicStoreExplicit(&g_enqueue_pause_wid, (int) wid, memory_order_release);
    atomicStoreExplicit(&g_enqueue_pause_stage, (int) stage, memory_order_release);
    atomicStoreExplicit(&g_enqueue_seam_reached, false, memory_order_release);
    atomicStoreExplicit(&g_enqueue_seam_release, false, memory_order_release);
    atomicStoreExplicit(&g_enqueue_seam_hits, 0, memory_order_release);
}

static void clearRaceSeam(void)
{
    atomicStoreExplicit(&g_enqueue_pause_wid, -1, memory_order_release);
    atomicStoreExplicit(&g_enqueue_pause_stage, -1, memory_order_release);
    atomicStoreExplicit(&g_enqueue_seam_release, true, memory_order_release);
}

static void waitForEnqueueSeamHits(int expected, const char *message)
{
    for (uint32_t attempt = 0; attempt < 5000U; ++attempt)
    {
        if (atomicLoadExplicit(&g_enqueue_seam_hits, memory_order_acquire) >= expected)
        {
            return;
        }
        wwSleepMS(1);
    }
    require(false, message);
}

static void requireRaceDisposition(const worker_message_race_t *race, bool expected_accepted)
{
    const bool accepted  = atomicLoadExplicit((atomic_bool *) &race->accepted, memory_order_acquire);
    const int  delivered = (int) atomicLoadExplicit((atomic_int *) &race->delivered, memory_order_relaxed);
    const int  cleaned   = (int) atomicLoadExplicit((atomic_int *) &race->cleaned, memory_order_relaxed);
    const int  returned  = (int) atomicLoadExplicit((atomic_int *) &race->returned, memory_order_relaxed);
    if (race->kind != kRacePostNormal)
    {
        require(accepted == expected_accepted, "raced message reported the wrong admission result");
    }
    require(delivered == 0, "startup-teardown race unexpectedly delivered a callback");
    if (race->kind == kRacePostNormal)
    {
        require(cleaned == 0 && returned == 0, "ordinary raced message unexpectedly acquired a cleanup owner");
        return;
    }
    require(delivered + cleaned + returned == 1, "raced payload was leaked or disposed more than once");
    if (race->kind == kRacePostRetainOnRefusal && ! accepted)
    {
        require(cleaned == 0 && returned == 1, "retain-on-refusal did not preserve caller ownership");
    }
    else
    {
        require(cleaned == 1 && returned == 0, "cleanup-owned raced message was not cleaned exactly once");
    }
}

static void runTeardownWinsRace(wid_t wid, race_post_kind_e kind)
{
    worker_message_race_t race;
    initializeRace(&race, wid, kind);
    configureRaceSeam(wid, kWorkerMessageEnqueueBeforeLifetimeLock);

    wthread_t poster;
    require(threadCreate(&poster, racePosterRoutine, &race) == kWThreadErrorNone,
            "failed to start teardown-wins poster");
    waitForAtomicBool(&g_enqueue_seam_reached, "poster did not reach the pre-lifetime-lock seam");
    require(workerExitJoin(getWorker(wid)), "teardown-wins worker teardown failed");
    atomicStoreExplicit(&race.teardown_done, true, memory_order_release);
    atomicStoreExplicit(&g_enqueue_seam_release, true, memory_order_release);
    require(threadJoin(poster) == 0, "failed to join teardown-wins poster");
    waitForAtomicBool(&race.poster_done, "teardown-wins poster did not finish");
    requireRaceDisposition(&race, false);
    clearRaceSeam();
}

static void runEnqueueWinsRace(wid_t wid, race_post_kind_e kind)
{
    worker_message_race_t race;
    initializeRace(&race, wid, kind);

    worker_t             *worker = getWorker(wid);
    worker_loop_blocker_t blocker;
    atomic_init(&blocker.entered, false);
    atomic_init(&blocker.release, false);
    atomic_init(&blocker.nested_runs, 0);
    atomic_init(&blocker.nested_cleanups, 0);
    blocker.run_nested_after_close = true;
    require(sendWorkerMessageForceQueueWithCleanup(
                wid, (WorkerMessageCallback) workerLoopBlockerCallback, NULL, &blocker, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "failed to install the enqueue-wins loop blocker");
    waitForAtomicBool(&blocker.entered, "target loop did not enter the enqueue-wins blocker");

    configureRaceSeam(wid, kWorkerMessageEnqueueBeforeEnqueue);

    wthread_t poster;
    wthread_t teardown;
    require(threadCreate(&poster, racePosterRoutine, &race) == kWThreadErrorNone,
            "failed to start enqueue-wins poster");
    waitForAtomicBool(&g_enqueue_seam_reached, "poster did not reach the pre-queue-lock seam");
    require(threadCreate(&teardown, raceTeardownRoutine, &race) == kWThreadErrorNone,
            "failed to start enqueue-wins teardown");
    atomicStoreExplicit(&g_enqueue_seam_release, true, memory_order_release);
    require(workerWaitForPhase(worker, kWorkerLifecycleQuiesceRequested, 5000),
            "enqueue-wins teardown did not close admission");
    for (uint32_t attempt = 0; attempt < 5000U && wloopNormalDispatchAllowed(worker->loop); ++attempt)
    {
        wwSleepMS(1);
    }
    require(! wloopNormalDispatchAllowed(worker->loop), "enqueue-wins teardown did not close normal dispatch");
    atomicStoreExplicit(&blocker.release, true, memory_order_release);
    require(threadJoin(poster) == 0, "failed to join enqueue-wins poster");
    require(threadJoin(teardown) == 0, "failed to join enqueue-wins teardown");
    waitForAtomicBool(&race.poster_done, "enqueue-wins poster did not finish");
    waitForAtomicBool(&race.teardown_done, "enqueue-wins teardown did not finish");
    requireRaceDisposition(&race, true);
    require(atomicLoadRelaxed(&blocker.nested_runs) == 1,
            "an admitted callback could not finish its synchronous nested call after closure");
    require(atomicLoadRelaxed(&blocker.nested_cleanups) == 0,
            "synchronous nested work was canceled after its callback root was admitted");
    clearRaceSeam();
}

#ifdef WW_WORKER_MESSAGE_LINK_WRAP
static void testWakeupFailurePreservesBothOwnershipContracts(void)
{
    worker_message_race_t race;
    atomicStoreExplicit(&g_fail_wakeup_post, true, memory_order_release);

    initializeRace(&race, 5, kRacePostWithCleanup);
    racePosterRoutine(&race);
    requireRaceDisposition(&race, false);

    initializeRace(&race, 5, kRacePostRetainOnRefusal);
    racePosterRoutine(&race);
    requireRaceDisposition(&race, false);

    initializeRace(&race, 5, kRacePostTimed);
    racePosterRoutine(&race);
    requireRaceDisposition(&race, false);

    atomicStoreExplicit(&g_fail_wakeup_post, false, memory_order_release);
}

static void testTimerAllocationFailureRefusesWithoutEarlyExecution(void)
{
    probeReset();
    eventloopTestFailNextTryZalloc();
    require(sendWorkerMessageTimedWithCleanup(
                0, (WorkerMessageCallback) probeCallback, probeCleanup, 25U, NULL, NULL, NULL) ==
                kWorkerMessageSubmitRejectedCleanupRan,
            "timer-allocation failure was reported as an armed delayed task");

    require(atomicLoadRelaxed(&g_probe.ran) == 0,
            "timer-allocation failure executed a minimum-delay callback synchronously");
    require(atomicLoadRelaxed(&g_probe.cleaned) == 1,
            "timer-allocation refusal did not run ownership cleanup exactly once");
}

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
static void testTimedRearmRefusalInIsolatedProcess(void)
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

static void testWorkerMessageBatchOrderingAndFairness(void)
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

static void testWorkerMessageFullBatchFifoAndFairness(void)
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
static void testWorkerMessageHardSuccessorWakeFallback(void)
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

static void testLocalBatchCleanupCannotReadmitInIsolatedProcess(void)
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

static void testLocalBatchQuiescencePositionsInIsolatedProcess(void)
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

static void testPendingCleanupReentryInIsolatedProcess(void)
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

static void testForeignDelayedCancellationInIsolatedProcess(void)
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

static void testDelayedPatternCompletionAndCancellationInIsolatedProcess(void)
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

static void testMessageAdmissionRacesWorkerTeardown(void)
{
    /* Exercise a live target before the teardown-race cases permanently close
     * worker admission for workers 1 through 8. The pipe fixture finalizes all
     * chain-owned pools before it publishes workers_run_flag, so worker startup
     * cannot race global allocation-padding construction. */
    testPipePublicationIsLinearizedWithPreStop();
    testPipePayloadFinishLateAndRefused();
    testWorkerMessageBatchOrderingAndFairness();
    testWorkerMessageFullBatchFifoAndFairness();
#ifdef WW_WORKER_MESSAGE_LINK_WRAP
    testWorkerMessageHardSuccessorWakeFallback();
    testWakeupFailurePreservesBothOwnershipContracts();
    testTimerAllocationFailureRefusesWithoutEarlyExecution();
#endif
    runTeardownWinsRace(1, kRacePostNormal);
    runTeardownWinsRace(2, kRacePostWithCleanup);
    runTeardownWinsRace(3, kRacePostRetainOnRefusal);
    runTeardownWinsRace(4, kRacePostTimed);
    runEnqueueWinsRace(5, kRacePostNormal);
    runEnqueueWinsRace(6, kRacePostWithCleanup);
    runEnqueueWinsRace(7, kRacePostRetainOnRefusal);
    runEnqueueWinsRace(8, kRacePostTimed);
}

static void testAdmissionOpenIsOneWayAndChecked(void)
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
    mutexDestroy(&incomplete.control_mutex);

    require(! workerMessagesOpenAdmission(getWorker(0)), "duplicate message-admission open was accepted");
    require(! workerMessagesOpenAdmission(getWorker(getTotalWorkersCount() - 1)),
            "pseudo-worker message admission was accepted");
}

static int probeRuns(void)
{
    return (int) atomicLoadExplicit(&g_probe.ran, memory_order_relaxed);
}

static int probeCleanups(void)
{
    return (int) atomicLoadExplicit(&g_probe.cleaned, memory_order_relaxed);
}

static void testOwningWorkerOutsideCallbackQueues(void)
{
    probeReset();
    sendWorkerMessageWithCleanup(0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    require(probeRuns() == 0, "same-worker message outside a callback executed inline");
    require(probeCleanups() == 0, "queued same-worker message ran cleanup before settlement");
}

static void testOtherEventWorkerQueues(void)
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

static void testUnregisteredThreadQueues(void)
{
    probeReset();

    wthread_t thread;
    require(threadCreate(&thread, unregisteredPosterRoutine, NULL) == kWThreadErrorNone,
            "failed to spawn unregistered poster thread");
    require(threadJoin(thread) == 0, "failed to join unregistered poster thread");

    require(probeRuns() == 0, "unregistered thread executed a worker message inline");
    require(probeCleanups() == 0, "queued message from an unregistered thread ran its cleanup");
}

static void testLwipPseudoWorkerQueues(void)
{
    probeReset();

    testWorkerBindWID(getTotalWorkersCount() - 1);
    sendWorkerMessageWithCleanup(0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    testWorkerBindWID(0);

    require(probeRuns() == 0, "lwIP pseudo-worker executed a worker message inline");
    require(probeCleanups() == 0, "message queued from lwIP ran its cleanup");
}

static void testInvalidTargetsCleanUpExactlyOnce(void)
{
    const wid_t lwip_wid = getTotalWorkersCount() - 1;

    const wid_t bad_targets[] = {kInvalidWID, (wid_t) getTotalWorkersCount(), lwip_wid};

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

typedef struct teardown_admission_probe_s
{
    atomic_int callbacks;
    atomic_int cleanups;
    atomic_int outer_cleanups;
    atomic_int cleanup_on_owner;
} teardown_admission_probe_t;

typedef struct line_refusal_poster_s
{
    line_t                   *line;
    sbuf_t                   *buf;
    bool                      with_buffer;
    bool                      bind_lwip;
    line_task_submit_result_e result;
} line_refusal_poster_t;

typedef struct line_buffer_lifetime_s
{
    sbuf_lifetime_t base;
    atomic_int      releases;
} line_buffer_lifetime_t;

typedef struct line_refcount_publication_s
{
    line_t *line;
} line_refcount_publication_t;

static WTHREAD_ROUTINE(lineFinalReleaseRoutine)
{
    line_refcount_publication_t *publication = userdata;

    require(getWID() == kInvalidWID, "final-release fixture inherited an event-worker identity");

    /* The line reference count is deliberately the only publication channel.
     * This relaxed poll supplies no ordering: lineUnref()'s final RMW and
     * acquire semantics must acquire the owner's 2 -> 1 release. */
    while (atomicLoadExplicit(&publication->line->refc, memory_order_relaxed) != 1U)
    {
        YIELD_THREAD();
    }
    lineUnref(publication->line);
    return 0;
}

static void testLineRefcountPublishesTeardownToFinalReleaser(void)
{
    master_pool_t *master = masterpoolCreateWithCapacity(4);
    require(master != NULL, "failed to create refcount-publication master pool");

    generic_pool_t *pool = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
        master, (uint32_t) (sizeof(line_t) + kCpuLineCacheSize), 2);
    require(pool != NULL, "failed to create refcount-publication line pool");
    generic_pool_t *pools[] = {pool};
    line_t         *line    = lineCreateForWorker(0, pools, 0);
    lineRef(line);

    line_refcount_publication_t publication = {.line = line};
    wthread_t                   final_releaser;
    require(threadCreate(&final_releaser, lineFinalReleaseRoutine, &publication) == kWThreadErrorNone,
            "failed to start the refcount-only final releaser");

    /* These writes occur after the foreign thread starts. No seam flag,
     * worker mutex, or condition variable publishes them. */
    lineAddUser(line, NULL, "published-user", "published-password");
    line->routing_context.dest_ctx.domain = stringDuplicate("published.example");
    memorySet(&line->tunnels_line_state[0], 0xA5, kCpuLineCacheSize);
    memoryZero(&line->tunnels_line_state[0], kCpuLineCacheSize);

    const size_t shared_returns_before = atomicLoadExplicit(&master->len, memory_order_acquire);
    lineDestroy(line);
    require(threadJoin(final_releaser) == 0, "failed to join the refcount-only final releaser");

    require(genericpoolGetInUse(pool) == 0, "refcount-only final release left a checked-out line");
    require(atomicLoadExplicit(&master->len, memory_order_acquire) == shared_returns_before + 1U,
            "refcount-only final release did not return exactly one line through the shared master");

    genericpoolDestroy(pool);
    masterpoolMakeEmpty(master);
    masterpoolDestroy(master);
}

static void lineBufferLifetimeRetain(sbuf_lifetime_t *base)
{
    discard base;
    require(false, "line refusal test unexpectedly cloned its buffer lifetime");
}

static void lineBufferLifetimeRelease(sbuf_lifetime_t *base)
{
    line_buffer_lifetime_t *lifetime = (line_buffer_lifetime_t *) base;
    atomicAddExplicit(&lifetime->releases, 1, memory_order_relaxed);
}

static void refusedLineTask(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    require(false, "refused line task unexpectedly ran");
}

static void refusedLineTaskWithBuffer(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    discard line;
    discard buf;
    require(false, "refused buffered line task unexpectedly ran");
}

static WTHREAD_ROUTINE(lineRefusalPosterRoutine)
{
    line_refusal_poster_t *poster = userdata;
    require(getWID() == kInvalidWID, "line-refusal poster inherited a worker identity");
    if (poster->bind_lwip)
    {
        testWorkerBindWID(getTotalWorkersCount() - 1);
    }

    if (poster->with_buffer)
    {
        poster->result = lineScheduleTaskWithBuf(poster->line, refusedLineTaskWithBuffer, NULL, poster->buf, NULL);
    }
    else
    {
        poster->result = lineScheduleTask(poster->line, refusedLineTask, NULL, NULL);
    }

    if (poster->bind_lwip)
    {
        testWorkerUnbindWID();
    }
    return 0;
}

static void exerciseForeignFinalLineReleaseDuringDetach(void)
{
    testLineRefcountPublishesTeardownToFinalReleaser();

    master_pool_t *master = masterpoolCreateWithCapacity(8);
    require(master != NULL, "failed to create foreign-release line master pool");

    generic_pool_t *pool = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
        master, (uint32_t) (sizeof(line_t) + kCpuLineCacheSize), 4);
    require(pool != NULL, "failed to create foreign-release line pool");
    generic_pool_t *other_pool = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
        master, (uint32_t) (sizeof(line_t) + kCpuLineCacheSize), 4);
    require(other_pool != NULL, "failed to create second foreign-release line pool");
    generic_pool_t *pools[] = {pool, other_pool};

    /* Control: an ordinary event-worker terminal release stays local. */
    line_t        *control                         = lineCreateForWorker(0, pools, 0);
    const uint32_t local_len_before_control_return = pool->len;
    require(genericpoolGetInUse(pool) == 1, "line pool did not account for its checked-out control line");
    lineDestroy(control);
    require(genericpoolGetInUse(pool) == 0 && pool->len == local_len_before_control_return + 1,
            "event-worker final release did not return to the local line pool");

    line_t *plain_line = lineCreateForWorker(0, pools, 0);
    line_t *lwip_line  = lineCreateForWorker(1, pools, 0);
    lineAddUser(plain_line, NULL, "plain-user", "plain-password");
    lineAddUser(lwip_line, NULL, "lwip-user", "lwip-password");
    plain_line->routing_context.dest_ctx.domain = stringDuplicate("plain.example");
    lwip_line->routing_context.dest_ctx.domain  = stringDuplicate("lwip.example");

    line_buffer_lifetime_t lifetime = {
        .base = {.retain = lineBufferLifetimeRetain, .release = lineBufferLifetimeRelease},
    };
    atomic_init(&lifetime.releases, 0);
    sbuf_t *buf = sbufCreate(32);
    require(buf != NULL, "failed to create refused line-task buffer");
    sbufAttachLifetime(buf, &lifetime.base);

    line_refusal_poster_t plain = {.line = plain_line};
    line_refusal_poster_t lwip  = {.line = lwip_line, .buf = buf, .with_buffer = true, .bind_lwip = true};
    configureRaceSeam(0, kWorkerMessageEnqueueBeforeLifetimeLock);

    wthread_t plain_thread;
    wthread_t lwip_thread;
    require(threadCreate(&plain_thread, lineRefusalPosterRoutine, &plain) == kWThreadErrorNone,
            "failed to create plain line-refusal poster");
    require(threadCreate(&lwip_thread, lineRefusalPosterRoutine, &lwip) == kWThreadErrorNone,
            "failed to create lwIP line-refusal poster");
    waitForEnqueueSeamHits(2, "line-refusal posters did not both retain their lines before detach");

    require(atomicLoadRelaxed(&plain_line->refc) == 2 && atomicLoadRelaxed(&lwip_line->refc) == 2,
            "line-refusal posters did not hold exactly one scheduling reference");
    lineDestroy(plain_line);
    lineDestroy(lwip_line);
    require(! lineIsAlive(plain_line) && ! lineIsAlive(lwip_line),
            "owner destruction did not make both refused-task lines logically dead");

    teardownCurrentWorker(getWorker(0));
    atomicStoreExplicit(&g_enqueue_seam_release, true, memory_order_release);
    require(threadJoin(plain_thread) == 0, "failed to join plain line-refusal poster");
    require(threadJoin(lwip_thread) == 0, "failed to join lwIP line-refusal poster");
    clearRaceSeam();

    require(plain.result == kLineTaskSubmitRejectedSettled && lwip.result == kLineTaskSubmitRejectedSettled,
            "post-detach line scheduling did not report settled rejection");
    require(atomicLoadRelaxed(&lifetime.releases) == 1,
            "refused buffered task did not destroy its standalone buffer exactly once");
    require(genericpoolGetInUse(pool) == 0, "foreign final line release left checked-out pool items");
    require(genericpoolGetInUse(other_pool) == 0,
            "cross-local-pool line migration corrupted family-wide outstanding accounting");
    require(atomicLoadExplicit(&master->len, memory_order_acquire) == 2,
            "plain/lwIP final releases did not return exactly two lines through the shared master pool");

    genericpoolDestroy(pool);
    genericpoolDestroy(other_pool);
    masterpoolMakeEmpty(master);
    masterpoolDestroy(master);
}

static void teardownAdmissionCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    teardown_admission_probe_t *probe = arg1;
    discard                     worker;
    discard                     arg2;
    discard                     arg3;
    atomicAddExplicit(&probe->callbacks, 1, memory_order_relaxed);
}

static void teardownAdmissionCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                     reason;
    teardown_admission_probe_t *probe = arg1;
    discard                     arg2;
    discard                     arg3;
    atomicAddExplicit(&probe->cleanups, 1, memory_order_relaxed);
}

static void teardownOuterCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                     reason;
    teardown_admission_probe_t *probe = arg1;
    discard                     arg2;
    discard                     arg3;

    atomicAddExplicit(&probe->outer_cleanups, 1, memory_order_relaxed);
    if (currentThreadIsEventWorkerWID(0))
    {
        atomicAddExplicit(&probe->cleanup_on_owner, 1, memory_order_relaxed);
    }

    /* TLS still names worker 0 here, but the admission transition has already
     * closed. Neither the inline nor timed form may resurrect work. */
    sendWorkerMessageWithCleanup(
        0, (WorkerMessageCallback) teardownAdmissionCallback, teardownAdmissionCleanup, probe, NULL, NULL);
    require(! sendWorkerMessageTimedWithCleanup(
                0, (WorkerMessageCallback) teardownAdmissionCallback, teardownAdmissionCleanup, 10U, probe, NULL, NULL),
            "timed work was admitted from detached-queue cleanup");
}

static void testTeardownCleanupCannotReadmitMessages(void)
{
    teardown_admission_probe_t probe;
    memoryZero(&probe, sizeof(probe));

    require(sendWorkerMessageForceQueueWithCleanup(
                0, (WorkerMessageCallback) teardownAdmissionCallback, teardownOuterCleanup, &probe, NULL, NULL),
            "failed to queue teardown admission probe");

    exerciseForeignFinalLineReleaseDuringDetach();

    require(atomicLoadRelaxed(&probe.callbacks) == 0, "a teardown probe callback ran after admission closed");
    require(atomicLoadRelaxed(&probe.outer_cleanups) == 1, "pending teardown cleanup did not run exactly once");
    require(atomicLoadRelaxed(&probe.cleanup_on_owner) == 1,
            "pending cleanup no longer observed its worker TLS identity");
    require(atomicLoadRelaxed(&probe.cleanups) == 2,
            "inline/timed teardown refusals did not clean their payloads exactly once");

    sendWorkerMessageWithCleanup(
        0, (WorkerMessageCallback) teardownAdmissionCallback, teardownAdmissionCleanup, &probe, NULL, NULL);
    require(! sendWorkerMessageForceQueueWithCleanup(
                0, (WorkerMessageCallback) teardownAdmissionCallback, teardownAdmissionCleanup, &probe, NULL, NULL),
            "queued work was admitted after worker detachment");
    require(atomicLoadRelaxed(&probe.callbacks) == 0, "a post-detach callback ran");
    require(atomicLoadRelaxed(&probe.cleanups) == 4,
            "post-detach immediate/queued refusals did not clean exactly once");
    require(! workerMessagesOpenAdmission(getWorker(0)), "message admission reopened after resource destruction");
}

// ---------------------------------------------------------------------------
// Tunnel-API buffer ownership
// ---------------------------------------------------------------------------

static void testTunnelApiHelpersRejectNonEventWorkers(void)
{
    // A standalone buffer, so the rejection path may destroy it outright.
    sbuf_t *message = sbufCreateWithPadding(64, 0);
    require(message != NULL, "failed to allocate a standalone API message");

    testWorkerUnbindWID();
    api_result_t result = tunnelapiRecycleMessage(message);
    require(result.result_code == kApiResultError, "tunnel API helper accepted an unregistered caller");
    testWorkerBindWID(0);

    message = sbufCreateWithPadding(64, 0);
    require(message != NULL, "failed to allocate a standalone API message");

    testWorkerBindWID(getTotalWorkersCount() - 1);
    result = tunnelapiRecycleMessage(message);
    require(result.result_code == kApiResultError, "tunnel API helper accepted the lwIP pseudo-worker");
    testWorkerBindWID(0);

    // On the owning event worker the buffer goes back to that worker's pool.
    sbuf_t *pooled = bufferpoolGetSmallBuffer(getCurrentEventWorkerBufferPool());
    require(pooled != NULL, "failed to take a buffer from worker 0's pool");
    result = tunnelapiRecycleMessage(pooled);
    require(result.result_code == kApiResultOk, "tunnel API helper rejected the owning event worker");
}

// ---------------------------------------------------------------------------
// Fallible APIs that must reject a bad worker in release builds too
// ---------------------------------------------------------------------------

/*
 * These are the paths where an assertion is not enough: they are reachable from
 * device threads and from cross-worker code, and in a release build an
 * assert-only guard would let a foreign caller reach another worker's state.
 */

static void probeDnsResult(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                           size_t naddrs)
{
    discard userdata;
    discard status;
    discard error;
    discard addrs;
    discard naddrs;

    require(false, "a rejected resolve request still invoked its callback");
}

static void probeLineDnsResult(tunnel_t *t, line_t *l, void *userdata, int status, const char *error,
                               const dns_resolved_addr_t *addrs, size_t naddrs)
{
    discard t;
    discard l;
    discard userdata;
    discard status;
    discard error;
    discard addrs;
    discard naddrs;

    require(false, "a rejected line resolve request still invoked its callback");
}

static WTHREAD_ROUTINE(unregisteredResolveRoutine)
{
    atomic_int *rc = userdata;

    require(getWID() == kInvalidWID, "resolve probe thread was not unregistered");
    atomicStoreRelaxed(rc, workerResolveDomainAsync(0, "example.invalid", probeDnsResult, NULL));
    return 0;
}

static void testResolverRejectsForeignCallers(void)
{
    // Worker 0 asking worker 1's resolver: rejected, no resolver touched.
    require(workerResolveDomainAsync(1, "example.invalid", probeDnsResult, NULL) == ARES_ENOTINITIALIZED,
            "resolver accepted a foreign worker id");

    // Out of range, and the lwIP pseudo-worker which has no resolver at all.
    require(workerResolveDomainAsync(kInvalidWID, "example.invalid", probeDnsResult, NULL) == ARES_ENOTINITIALIZED,
            "resolver accepted kInvalidWID");
    require(workerResolveDomainAsync(getTotalWorkersCount() - 1, "example.invalid", probeDnsResult, NULL) ==
                ARES_ENOTINITIALIZED,
            "resolver accepted the lwIP pseudo-worker");

    // An unregistered thread must be rejected without touching worker 0.
    atomic_int rc;
    atomicStoreRelaxed(&rc, 0);
    wthread_t thread;
    require(threadCreate(&thread, unregisteredResolveRoutine, &rc) == kWThreadErrorNone,
            "failed to spawn resolve probe thread");
    require(threadJoin(thread) == 0, "failed to join resolve probe thread");
    require(atomicLoadRelaxed(&rc) == ARES_ENOTINITIALIZED, "resolver accepted an unregistered thread");
}

static void testLineResolverRejectsForeignCallers(void)
{
    // A line owned by worker 1, queried from worker 0: rejected before the
    // line is even referenced, so a failed call cannot leak a line reference.
    line_t foreign_line = {.wid = 1, .alive = true};
    atomicStoreRelaxed(&foreign_line.refc, 1);

    require(lineResolveDomainAsync(&foreign_line, "example.invalid", probeLineDnsResult, NULL, NULL) ==
                ARES_ENOTINITIALIZED,
            "line resolver accepted a foreign worker");
    require(atomicLoadRelaxed(&foreign_line.refc) == 1, "rejected line resolve leaked a line reference");

    line_t lwip_line = {.wid = (wid_t) (getTotalWorkersCount() - 1), .alive = true};
    atomicStoreRelaxed(&lwip_line.refc, 1);
    require(lineResolveDomainAsync(&lwip_line, "example.invalid", probeLineDnsResult, NULL, NULL) ==
                ARES_ENOTINITIALIZED,
            "line resolver accepted a line owned by the lwIP pseudo-worker");
    require(atomicLoadRelaxed(&lwip_line.refc) == 1, "rejected line resolve leaked a line reference");
}

static line_t *allocateLineForTunnel(tunnel_t *owner, wid_t wid)
{
    line_t *line = memoryAllocateCacheAlignedZero(sizeof(line_t) + tunnelGetLineStateSize(owner));
    require(line != NULL, "failed to allocate a pipe test line");
    atomicStoreRelaxed(&line->refc, 1);
    line->alive = true;
    line->wid   = wid;
    return line;
}

static void testPipeToRejectsBadWorkers(void)
{
    tunnel_t *child = tunnelCreate(NULL, 0, 0);
    require(child != NULL, "failed to create the pipe test child tunnel");

    tunnel_t *pipe_tunnel = pipetunnelCreate(child);
    require(pipe_tunnel != NULL, "failed to create the pipe tunnel");

    // pipeTo() takes the child and reaches its parent through t->prev; the pipe
    // line state sits at the parent's offset.
    child->prev                = pipe_tunnel;
    pipe_tunnel->lstate_offset = 0;

    line_t *owned_line = allocateLineForTunnel(pipe_tunnel, 0);

    /*
     * Self-target, the lwIP pseudo-worker and an out-of-range slot must all be
     * refused. In a release build these used to be unchecked, and pipeTo() would
     * go on to create a pair line for a worker that cannot own it.
     */
    require(! pipeTo(child, owned_line, 0), "pipeTo accepted the current worker as its target");
    require(! pipeTo(child, owned_line, (wid_t) (getTotalWorkersCount() - 1)),
            "pipeTo accepted the lwIP pseudo-worker as its target");
    require(! pipeTo(child, owned_line, kInvalidWID), "pipeTo accepted kInvalidWID as its target");
    require(! pipeTo(child, owned_line, (wid_t) getTotalWorkersCount()),
            "pipeTo accepted an out-of-range target worker");

    // A source line this worker does not own is refused as well.
    line_t *foreign_line = allocateLineForTunnel(pipe_tunnel, 1);
    require(! pipeTo(child, foreign_line, 0), "pipeTo accepted a source line owned by another worker");

    // Every rejection happened before any pair line was built.
    require(atomicLoadRelaxed(&owned_line->refc) == 1, "rejected pipeTo leaked a source line reference");
    require(atomicLoadRelaxed(&foreign_line->refc) == 1, "rejected pipeTo leaked a source line reference");

    memoryFreeAligned(foreign_line);
    memoryFreeAligned(owned_line);
    tunnelDestroy(pipe_tunnel);
}

static void requirePipeLineStateZero(tunnel_t *pipe_tunnel, line_t *line, const char *message)
{
    const uint8_t *state = lineGetState(line, pipe_tunnel);
    for (uint32_t i = 0; i < tunnelGetLineStateSize(pipe_tunnel); ++i)
    {
        require(state[i] == 0, message);
    }
}

static void pipeQueueBarrier(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;
    atomicStoreExplicit((atomic_bool *) arg1, true, memory_order_release);
}

static void testPipePublicationIsLinearizedWithPreStop(void)
{
    atomicStoreRelaxed(&g_pipe_init_count, 0);
    atomicStoreRelaxed(&g_pipe_owned_finish_count, 0);
    atomicStoreRelaxed(&g_pipe_borrowed_finish_count, 0);
    atomicStoreRelaxed(&g_pipe_owned_payload_count, 0);
    atomicStoreRelaxed(&g_pipe_borrowed_payload_count, 0);
    atomicStoreExplicit(&g_pipe_owned_line, NULL, memory_order_release);

    tunnel_t *previous = tunnelCreate(NULL, 0, 0);
    tunnel_t *child    = tunnelCreate(NULL, 0, 0);
    require(previous != NULL && child != NULL, "failed to create pipe publication endpoints");
    child->fnInitU       = pipeTestOwnedInit;
    child->fnPayloadU    = pipeTestOwnedPayload;
    child->fnFinU        = pipeTestOwnedFinish;
    previous->fnPayloadD = pipeTestBorrowedPayload;
    previous->fnFinD     = pipeTestBorrowedFinish;

    tunnel_t *pipe_tunnel = pipetunnelCreate(child);
    require(pipe_tunnel != NULL, "failed to create pipe publication tunnel");
    tunnelBind(previous, pipe_tunnel);
    tunnelBind(pipe_tunnel, child);
    pipe_tunnel->lstate_offset = 0;
    child->lstate_offset       = (uint32_t) (tunnelGetLineStateSize(pipe_tunnel) - tunnelGetLineStateSize(child));

    tunnel_chain_t *chain = tunnelchainCreate(getWorkersCount());
    require(chain != NULL, "failed to create pipe publication chain");
    chain->sum_line_state_size = tunnelGetLineStateSize(pipe_tunnel);
    previous->chain            = chain;
    pipe_tunnel->chain         = chain;
    child->chain               = chain;
    tunnelchainFinalize(chain);

    pipe_tunnel->onStart(pipe_tunnel);
    line_t *source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 1,
            "pipe stop-race fixture began with the wrong line count");

    atomicStoreExplicit(&g_pipe_stop_in_fast_check_seam, true, memory_order_release);
    require(! pipeTo(child, source, 1), "pipe publication crossed a completed PreStop transition");
    require(! atomicLoadExplicit(&g_pipe_stop_in_fast_check_seam, memory_order_acquire),
            "pipe fast-check stop seam was not reached");
    requirePipeLineStateZero(pipe_tunnel, source, "stop-winning pipeTo published source line state");
    require(atomicLoadRelaxed(&g_pipe_init_count) == 0, "stop-winning pipeTo emitted Init");
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 1,
            "stop-winning pipeTo retained its staged owned line");

    lineDestroy(source);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0,
            "stop-winning pipe fixture retained its borrowed source line");
    tunnelchainDestroy(chain);
    pipetunnelDestroy(pipe_tunnel, testShutdownContext());
    tunnelDestroy(previous);

    previous = tunnelCreate(NULL, 0, 0);
    child    = tunnelCreate(NULL, 0, 0);
    require(previous != NULL && child != NULL, "failed to recreate pipe publication endpoints");
    child->fnInitU       = pipeTestOwnedInit;
    child->fnPayloadU    = pipeTestOwnedPayload;
    child->fnFinU        = pipeTestOwnedFinish;
    previous->fnPayloadD = pipeTestBorrowedPayload;
    previous->fnFinD     = pipeTestBorrowedFinish;
    pipe_tunnel          = pipetunnelCreate(child);
    require(pipe_tunnel != NULL, "failed to recreate pipe publication tunnel");
    tunnelBind(previous, pipe_tunnel);
    tunnelBind(pipe_tunnel, child);
    pipe_tunnel->lstate_offset = 0;
    child->lstate_offset       = (uint32_t) (tunnelGetLineStateSize(pipe_tunnel) - tunnelGetLineStateSize(child));

    chain = tunnelchainCreate(getWorkersCount());
    require(chain != NULL, "failed to recreate pipe publication chain");
    chain->sum_line_state_size = tunnelGetLineStateSize(pipe_tunnel);
    previous->chain            = chain;
    pipe_tunnel->chain         = chain;
    child->chain               = chain;
    tunnelchainFinalize(chain);
    pipe_tunnel->onStart(pipe_tunnel);

    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    for (wid_t wid = 1; wid < getWorkersCount(); ++wid)
    {
        waitForAtomicBool(&getWorker(wid)->message_admission_open,
                          "worker did not open message admission for the live pipe fixture");
    }

    /* Earlier identity cases intentionally leave a worker-1 message queued
     * while the loops are stopped. Drain through a barrier before injecting a
     * wakeup-post refusal, otherwise that old wakeup legitimately coalesces the
     * new message before the refusal seam is reached. */
    atomic_bool barrier_ran;
    atomic_init(&barrier_ran, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeQueueBarrier, NULL, &barrier_ran, NULL, NULL),
            "failed to admit the pipe queue-drain barrier");
    waitForAtomicBool(&barrier_ran, "pipe queue-drain barrier did not run on worker 1");

#ifdef WW_WORKER_MESSAGE_LINK_WRAP
    const worker_message_enqueue_test_failure_e pipe_failures[] = {
        kWorkerMessageEnqueueFailDequeGrowth,
        kWorkerMessageEnqueueFailWakeupPost,
    };
    atomicStoreRelaxed(&g_pipe_shutdown_requests, 0);
    for (uint32_t failure_index = 0; failure_index < ARRAY_SIZE(pipe_failures); ++failure_index)
    {
        line_t *refused_source = lineCreate(tunnelchainGetLinePools(chain), 0);
        workerMessagesEnqueueTestSetFailure(pipe_failures[failure_index]);
        require(! pipeTo(child, refused_source, 1), "pipe Init queue refusal was reported as admitted");
        requirePipeLineStateZero(pipe_tunnel, refused_source, "pipe Init refusal retained borrowed line state");
        require(atomicLoadRelaxed(&g_pipe_init_count) == 0, "pipe Init refusal ran a late callback");
        require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 1,
                "pipe Init refusal retained its staged owned line or pair reference");
        lineDestroy(refused_source);
        require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0,
                "pipe Init refusal retained the borrowed source allocation");
    }
    require(atomicLoadRelaxed(&g_pipe_shutdown_requests) == ARRAY_SIZE(pipe_failures),
            "pipe queue refusals did not each request one terminal reconciliation");
#endif

    source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(pipeTo(child, source, 1), "publication-winning pipeTo rejected a valid pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 1; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 1, "publication-winning pipe Init did not reach worker 1");

    pipe_payload_lifetime_t up_lifetime;
    pipe_tunnel->fnPayloadU(pipe_tunnel, source, pipeTestPayload(&up_lifetime));
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_owned_payload_count) != 1; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_owned_payload_count) == 1,
            "pipe upstream Payload did not reach the owned line exactly once");
    require(atomicLoadRelaxed(&up_lifetime.releases) == 1, "pipe upstream Payload was not released exactly once");

    pipe_payload_lifetime_t down_lifetime;
    pipe_down_call_t        down_call = {
               .wrapper = pipe_tunnel,
               .line    = atomicLoadExplicit(&g_pipe_owned_line, memory_order_acquire),
               .payload = pipeTestPayload(&down_lifetime),
               .finish  = false,
    };
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeDownCallOnWorker, NULL, &down_call, NULL, NULL),
            "failed to admit the pipe downstream Payload fixture");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_borrowed_payload_count) != 1; ++attempt)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_borrowed_payload_count) == 1,
            "pipe downstream Payload did not reach the borrowed line exactly once");
    require(atomicLoadRelaxed(&down_lifetime.releases) == 1, "pipe downstream Payload was not released exactly once");

    line_t *upstream_finished_source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(pipeTo(child, upstream_finished_source, 1), "failed to create the upstream-Finish pipe pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 2; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 2, "upstream-Finish pair Init did not reach worker 1");
    pipe_tunnel->fnFinU(pipe_tunnel, upstream_finished_source);
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_owned_finish_count) != 1; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_owned_finish_count) == 1,
            "upstream Finish did not close the owned role exactly once");
    require(atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 0,
            "upstream Finish reflected back toward its already-finished sender");
    require(lineIsAlive(upstream_finished_source), "pipe destroyed its borrowed upstream-Finish line");
    requirePipeLineStateZero(
        pipe_tunnel, upstream_finished_source, "upstream Finish retained the borrowed line-state attachment");
    lineDestroy(upstream_finished_source);

    line_t *downstream_finished_source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(pipeTo(child, downstream_finished_source, 1), "failed to create the downstream-Finish pipe pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 3; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 3, "downstream-Finish pair Init did not reach worker 1");
    pipe_down_call_t finish_call = {
        .wrapper = pipe_tunnel,
        .line    = atomicLoadExplicit(&g_pipe_owned_line, memory_order_acquire),
        .finish  = true,
    };
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeDownCallOnWorker, NULL, &finish_call, NULL, NULL),
            "failed to admit the pipe downstream Finish fixture");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_borrowed_finish_count) != 1; ++attempt)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 1,
            "downstream Finish did not close the borrowed role exactly once");
    require(atomicLoadRelaxed(&g_pipe_owned_finish_count) == 1,
            "downstream Finish reflected back toward its already-finished sender");
    require(lineIsAlive(downstream_finished_source), "pipe destroyed its borrowed downstream-Finish line");
    requirePipeLineStateZero(
        pipe_tunnel, downstream_finished_source, "downstream Finish retained the borrowed line-state attachment");
    lineDestroy(downstream_finished_source);

    line_t *worker_stop_source = lineCreate(tunnelchainGetLinePools(chain), 0);
    require(pipeTo(child, worker_stop_source, 1), "failed to create the worker-stop pipe pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 4; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 4, "worker-stop pair Init did not reach worker 1");
    pipe_tunnel->onWorkerStop(pipe_tunnel, 0, testShutdownContext());
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeWorkerStopCall, NULL, pipe_tunnel, NULL, NULL),
            "failed to admit the pipe worker-1 stop fixture");
    atomic_bool worker_stop_completed;
    atomic_init(&worker_stop_completed, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeQueueBarrier, NULL, &worker_stop_completed, NULL, NULL),
            "failed to admit the pipe worker-stop barrier");
    waitForAtomicBool(&worker_stop_completed, "pipe worker-stop barrier did not run on worker 1");
    for (uint32_t attempt = 0; attempt < 5000 && (atomicLoadRelaxed(&g_pipe_owned_finish_count) != 3 ||
                                                  atomicLoadRelaxed(&g_pipe_borrowed_finish_count) != 3);
         ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_owned_finish_count) == 3 && atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 3,
            "worker-stop did not finish both roles of every live pipe pair exactly once");
    require(lineIsAlive(worker_stop_source), "worker-stop destroyed its borrowed source line");
    requirePipeLineStateZero(pipe_tunnel, worker_stop_source, "worker-stop retained borrowed line state");
    lineDestroy(worker_stop_source);

    pipe_tunnel->onStop(pipe_tunnel, testShutdownContext());
    require(lineIsAlive(source), "pipe stop destroyed its borrowed source line");
    requirePipeLineStateZero(pipe_tunnel, source, "pipe stop retained the borrowed line-state attachment");
    require(atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 3,
            "pipe stop did not finish the borrowed role exactly once");
    require(atomicLoadRelaxed(&g_pipe_owned_finish_count) == 3,
            "pipe stop did not finish the initialized owned role exactly once");
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 1,
            "pipe stop did not reclaim its owned line and pair references");

    lineDestroy(source);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0,
            "pipe publication fixture retained a line after final borrowed release");
    tunnelchainDestroy(chain);
    pipetunnelDestroy(pipe_tunnel, testShutdownContext());
    tunnelDestroy(previous);
}

typedef struct pipe_message_case_fixture_s
{
    tunnel_t       *previous;
    tunnel_t       *child;
    tunnel_t       *wrapper;
    tunnel_chain_t *chain;
    line_t         *borrowed;
    line_t         *owned;
} pipe_message_case_fixture_t;

static void pipeMessageCaseSetup(pipe_message_case_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    atomicStoreRelaxed(&g_pipe_init_count, 0);
    atomicStoreRelaxed(&g_pipe_owned_finish_count, 0);
    atomicStoreRelaxed(&g_pipe_borrowed_finish_count, 0);
    atomicStoreRelaxed(&g_pipe_owned_payload_count, 0);
    atomicStoreRelaxed(&g_pipe_borrowed_payload_count, 0);
    atomicStoreExplicit(&g_pipe_owned_line, NULL, memory_order_release);

    fixture->previous = tunnelCreate(NULL, 0, 0);
    fixture->child    = tunnelCreate(NULL, 0, 0);
    require(fixture->previous != NULL && fixture->child != NULL, "failed to create pipe message endpoints");
    fixture->child->fnInitU       = pipeTestOwnedInit;
    fixture->child->fnPayloadU    = pipeTestOwnedPayload;
    fixture->child->fnFinU        = pipeTestOwnedFinish;
    fixture->previous->fnPayloadD = pipeTestBorrowedPayload;
    fixture->previous->fnFinD     = pipeTestBorrowedFinish;

    fixture->wrapper = pipetunnelCreate(fixture->child);
    require(fixture->wrapper != NULL, "failed to create pipe message wrapper");
    tunnelBind(fixture->previous, fixture->wrapper);
    tunnelBind(fixture->wrapper, fixture->child);
    fixture->wrapper->lstate_offset = 0;
    fixture->child->lstate_offset =
        (uint32_t) (tunnelGetLineStateSize(fixture->wrapper) - tunnelGetLineStateSize(fixture->child));

    fixture->chain = tunnelchainCreate(getWorkersCount());
    require(fixture->chain != NULL, "failed to create pipe message chain");
    fixture->chain->sum_line_state_size = tunnelGetLineStateSize(fixture->wrapper);
    fixture->previous->chain            = fixture->chain;
    fixture->wrapper->chain             = fixture->chain;
    fixture->child->chain               = fixture->chain;
    tunnelchainFinalize(fixture->chain);
    fixture->wrapper->onStart(fixture->wrapper);

    fixture->borrowed = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    require(fixture->borrowed != NULL && pipeTo(fixture->child, fixture->borrowed, 1),
            "failed to publish the pipe message pair");
    for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_init_count) != 1; ++attempt)
    {
        wwSleepMS(1);
    }
    require(atomicLoadRelaxed(&g_pipe_init_count) == 1, "pipe message pair Init did not reach worker 1");
    fixture->owned = atomicLoadExplicit(&g_pipe_owned_line, memory_order_acquire);
    require(fixture->owned != NULL, "pipe message pair did not publish its owned line");
}

static void pipeMessageCaseDrainAndDestroy(pipe_message_case_fixture_t *fixture)
{
    fixture->wrapper->onQuiesceRequest(fixture->wrapper, testShutdownContext());
    fixture->wrapper->onWorkerStop(fixture->wrapper, 0, testShutdownContext());

    atomic_bool worker_done;
    atomic_init(&worker_done, false);
    require(sendWorkerMessageForceQueueWithCleanup(
                1, (WorkerMessageCallback) pipeWorkerStopCall, NULL, fixture->wrapper, &worker_done, NULL),
            "failed to admit the pipe message worker drain");
    waitForAtomicBool(&worker_done, "pipe message worker drain did not complete");

    require(lineIsAlive(fixture->borrowed), "pipe destroyed the borrowed message-case line");
    requirePipeLineStateZero(fixture->wrapper, fixture->borrowed, "pipe message case retained borrowed line state");
    lineDestroy(fixture->borrowed);
    require(masterpoolGetCheckedOut(fixture->chain->masterpool_line_pool) == 0,
            "pipe message case retained an owned line or pair reference");

    /* Repeated stop is intentionally harmless after both authoritative worker
     * inventories have been drained. */
    fixture->wrapper->onWorkerStop(fixture->wrapper, 0, testShutdownContext());
    tunnelchainDestroy(fixture->chain);
    pipetunnelDestroy(fixture->wrapper, testShutdownContext());
    tunnelDestroy(fixture->previous);
}

typedef struct pipe_blocking_barrier_s
{
    atomic_bool entered;
    atomic_bool release;
    atomic_bool done;
} pipe_blocking_barrier_t;

static void pipeBlockingBarrier(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                  worker;
    discard                  arg2;
    discard                  arg3;
    pipe_blocking_barrier_t *barrier = arg1;
    atomicStoreExplicit(&barrier->entered, true, memory_order_release);
    while (! atomicLoadExplicit(&barrier->release, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    atomicStoreExplicit(&barrier->done, true, memory_order_release);
}

static void pipeRunRefusalCase(bool upstream, bool finish, worker_message_enqueue_test_failure_e failure)
{
    pipe_message_case_fixture_t fixture;
    pipeMessageCaseSetup(&fixture);
    atomicStoreRelaxed(&g_pipe_shutdown_requests, 0);

    pipe_payload_lifetime_t lifetime;
    sbuf_t                 *payload = finish ? NULL : pipeTestPayload(&lifetime);
    if (upstream)
    {
        workerMessagesEnqueueTestSetFailure(failure);
        if (finish)
        {
            fixture.wrapper->fnFinU(fixture.wrapper, fixture.borrowed);
        }
        else
        {
            fixture.wrapper->fnPayloadU(fixture.wrapper, fixture.borrowed, payload);
        }
    }
    else
    {
        atomic_bool done;
        atomic_init(&done, false);
        pipe_down_call_t call = {
            .wrapper = fixture.wrapper,
            .line    = fixture.owned,
            .payload = payload,
            .done    = &done,
            .failure = failure,
            .finish  = finish,
        };
        require(sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) pipeDownCallOnWorker, NULL, &call, NULL, NULL),
                "failed to admit the pipe refusal driver");
        waitForAtomicBool(&done, "pipe refusal driver did not complete");
    }

    require(atomicLoadRelaxed(&g_pipe_shutdown_requests) == 1,
            "pipe Payload/Finish refusal did not request one terminal reconciliation");
    if (! finish)
    {
        require(atomicLoadRelaxed(&lifetime.releases) == 1, "refused pipe Payload was not recycled exactly once");
        require(atomicLoadRelaxed(&g_pipe_owned_payload_count) == 0 &&
                    atomicLoadRelaxed(&g_pipe_borrowed_payload_count) == 0,
                "refused pipe Payload reached a user callback");
    }
    pipeMessageCaseDrainAndDestroy(&fixture);
}

static void pipeRunAdmittedLateCase(bool upstream, bool finish)
{
    pipe_message_case_fixture_t fixture;
    pipeMessageCaseSetup(&fixture);

    pipe_payload_lifetime_t lifetime;
    sbuf_t                 *payload = finish ? NULL : pipeTestPayload(&lifetime);
    pipe_blocking_barrier_t barrier;
    memoryZero(&barrier, sizeof(barrier));
    atomic_init(&barrier.entered, false);
    atomic_init(&barrier.release, false);
    atomic_init(&barrier.done, false);

    if (upstream)
    {
        require(sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) pipeBlockingBarrier, NULL, &barrier, NULL, NULL),
                "failed to admit the pipe late-dispatch barrier");
        waitForAtomicBool(&barrier.entered, "pipe late-dispatch barrier did not stop worker 1");
        if (finish)
        {
            fixture.wrapper->fnFinU(fixture.wrapper, fixture.borrowed);
        }
        else
        {
            fixture.wrapper->fnPayloadU(fixture.wrapper, fixture.borrowed, payload);
        }
        fixture.wrapper->onQuiesceRequest(fixture.wrapper, testShutdownContext());
        atomicStoreExplicit(&barrier.release, true, memory_order_release);
        waitForAtomicBool(&barrier.done, "pipe late-dispatch barrier did not release worker 1");
        if (! finish)
        {
            for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&lifetime.releases) == 0; ++attempt)
            {
                wwSleepMS(1);
            }
        }
        else
        {
            for (uint32_t attempt = 0; attempt < 5000 && atomicLoadRelaxed(&g_pipe_owned_finish_count) == 0; ++attempt)
            {
                wwSleepMS(1);
            }
        }
    }
    else
    {
        atomic_bool done;
        atomic_init(&done, false);
        pipe_down_call_t call = {
            .wrapper = fixture.wrapper,
            .line    = fixture.owned,
            .payload = payload,
            .done    = &done,
            .failure = kWorkerMessageEnqueueFailNone,
            .finish  = finish,
        };
        require(sendWorkerMessageForceQueueWithCleanup(
                    1, (WorkerMessageCallback) pipeDownCallOnWorker, NULL, &call, NULL, NULL),
                "failed to admit the downstream late-dispatch driver");
        waitForAtomicBool(&done, "downstream late-dispatch driver did not admit its pipe message");
        fixture.wrapper->onQuiesceRequest(fixture.wrapper, testShutdownContext());
        for (uint32_t attempt = 0; attempt < 5000 && (! finish ? atomicLoadRelaxed(&lifetime.releases) == 0
                                                               : atomicLoadRelaxed(&g_pipe_borrowed_finish_count) == 0);
             ++attempt)
        {
            discard wloopProcessEvents(getWorkerLoop(0), 0);
            wwSleepMS(1);
        }
    }

    if (! finish)
    {
        require(atomicLoadRelaxed(&lifetime.releases) == 1, "late pipe Payload was not recycled exactly once");
        require(atomicLoadRelaxed(&g_pipe_owned_payload_count) == 0 &&
                    atomicLoadRelaxed(&g_pipe_borrowed_payload_count) == 0,
                "late pipe Payload crossed a terminal pair");
    }
    pipeMessageCaseDrainAndDestroy(&fixture);
}

static void testPipePayloadFinishLateAndRefused(void)
{
#ifdef WW_WORKER_MESSAGE_LINK_WRAP
    const worker_message_enqueue_test_failure_e failures[] = {
        kWorkerMessageEnqueueFailDequeGrowth,
        kWorkerMessageEnqueueFailWakeupPost,
    };
    for (uint32_t failure_index = 0; failure_index < ARRAY_SIZE(failures); ++failure_index)
    {
        for (uint32_t upstream = 0; upstream < 2; ++upstream)
        {
            pipeRunRefusalCase(upstream != 0, false, failures[failure_index]);
            pipeRunRefusalCase(upstream != 0, true, failures[failure_index]);
        }
    }
#endif

    pipeRunAdmittedLateCase(true, false);
    pipeRunAdmittedLateCase(true, true);
    pipeRunAdmittedLateCase(false, false);
    pipeRunAdmittedLateCase(false, true);
}

// ---------------------------------------------------------------------------
// Contract aborts (checked in a child process)
// ---------------------------------------------------------------------------

#if defined(HAS_UNIX_FORK)
typedef enum
{
    kAbortCaseUnregisteredPool = 0,
    kAbortCaseUnregisteredLoop,
    kAbortCaseUnregisteredReuseBuffer,
    kAbortCaseLwipPool,
    kAbortCaseCount
} abort_case_e;

static void runAbortCase(abort_case_e which)
{
    switch (which)
    {
    case kAbortCaseUnregisteredPool:
        testWorkerUnbindWID();
        discard getCurrentEventWorkerBufferPool();
        break;
    case kAbortCaseUnregisteredLoop:
        testWorkerUnbindWID();
        discard getCurrentEventWorkerLoop();
        break;
    case kAbortCaseUnregisteredReuseBuffer: {
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        testWorkerUnbindWID();
        reuseBuffer(buf);
        break;
    }
    case kAbortCaseLwipPool:
        testWorkerBindWID(getTotalWorkersCount() - 1);
        discard getCurrentEventWorkerBufferPool();
        break;
    case kAbortCaseCount:
    default:
        break;
    }
}

static void testCheckedAccessorsAbortOffEventWorkers(void)
{
    static const char *kNames[kAbortCaseCount] = {
        "getCurrentEventWorkerBufferPool() from an unregistered thread",
        "getCurrentEventWorkerLoop() from an unregistered thread",
        "reuseBuffer() from an unregistered thread",
        "getCurrentEventWorkerBufferPool() from the lwIP pseudo-worker",
    };

    for (int which = 0; which < (int) kAbortCaseCount; ++which)
    {
        pid_t pid = fork();
        require(pid >= 0, "fork failed for a checked-accessor abort case");
        if (pid == 0)
        {
            initTestGlobalState();
            runAbortCase((abort_case_e) which);
            // Reaching here means the accessor silently accepted the caller.
            exit(0);
        }

        int status = 0;
        require(waitpid(pid, &status, 0) == pid, "waitpid failed for a checked-accessor abort case");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 1, kNames[which]);
    }
}
#endif

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--line-refcount-publication-only") == 0)
    {
        testLineRefcountPublishesTeardownToFinalReleaser();
        return 0;
    }

    testWorkerMessageConstructionTransactional();
#if defined(WW_WORKER_MESSAGE_LINK_WRAP) && defined(HAS_UNIX_FORK)
    testTimedRearmRefusalInIsolatedProcess();
#endif
#if defined(HAS_UNIX_FORK)
    testLocalBatchCleanupCannotReadmitInIsolatedProcess();
    testLocalBatchQuiescencePositionsInIsolatedProcess();
    testPendingCleanupReentryInIsolatedProcess();
    testForeignDelayedCancellationInIsolatedProcess();
    testDelayedPatternCompletionAndCancellationInIsolatedProcess();
#endif
    initTestGlobalState();

    testAccessorsOnOwningWorker();
    testPredicatesRejectUnregisteredAndLwip();

    testOwningWorkerOutsideCallbackQueues();
    testTransactionalEnqueueFailureStages();
    testOtherEventWorkerQueues();
    testUnregisteredThreadQueues();
    testLwipPseudoWorkerQueues();
    testInvalidTargetsCleanUpExactlyOnce();
    testAdmissionOpenIsOneWayAndChecked();
    testMessageAdmissionRacesWorkerTeardown();

    testTunnelApiHelpersRejectNonEventWorkers();
    testResolverRejectsForeignCallers();
    testLineResolverRejectsForeignCallers();
    testPipeToRejectsBadWorkers();

    testTeardownCleanupCannotReadmitMessages();

    shutdownTestGlobalState();

#if defined(HAS_UNIX_FORK)
    testCheckedAccessorsAbortOffEventWorkers();
#endif

    return 0;
}
