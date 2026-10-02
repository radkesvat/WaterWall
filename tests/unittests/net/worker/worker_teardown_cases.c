/* Admission/teardown races, foreign final line release and cancellation after detach. These cases permanently close
 * worker slots; only the driver chooses their lifecycle phase. CTest: waterwall.worker_context_helpers_unit; see the
 * driver for ordering and CLI. */
#include "worker_fixture.h"

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

void runTeardownWinsRace(wid_t wid, race_post_kind_e kind)
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

void runEnqueueWinsRace(wid_t wid, race_post_kind_e kind)
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
void testWakeupFailurePreservesBothOwnershipContracts(void)
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

#endif
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
    bool                      bind_out_of_range;
    line_task_submit_result_e result;
} line_refusal_poster_t;

typedef struct line_buffer_lifetime_s
{

    atomic_uint releases;
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
    while (atomicLoadU32Explicit(&publication->line->refc, memory_order_relaxed) != 1U)
    {
        YIELD_THREAD();
    }
    lineUnref(publication->line);
    return 0;
}

void testLineRefcountPublishesTeardownToFinalReleaser(void)
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
    if (poster->bind_out_of_range)
    {
        testWorkerBindWID(getTotalWorkersCount());
    }

    if (poster->with_buffer)
    {
        poster->result = lineScheduleTaskWithBuf(poster->line, refusedLineTaskWithBuffer, NULL, poster->buf, NULL);
    }
    else
    {
        poster->result = lineScheduleTask(poster->line, refusedLineTask, NULL, NULL);
    }

    if (poster->bind_out_of_range)
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

    line_t *plain_line        = lineCreateForWorker(0, pools, 0);
    line_t *unregistered_line = lineCreateForWorker(1, pools, 0);
    lineAddUser(plain_line, NULL, "plain-user", "plain-password");
    lineAddUser(unregistered_line, NULL, "lwip-user", "lwip-password");
    plain_line->routing_context.dest_ctx.domain        = stringDuplicate("plain.example");
    unregistered_line->routing_context.dest_ctx.domain = stringDuplicate("lwip.example");

    line_buffer_lifetime_t lifetime = {0};
    atomic_init(&lifetime.releases, 0);
    sbuf_t *buf = sbufCreate(32);
    require(buf != NULL, "failed to create refused line-task buffer");
    watchBufferDisposal(buf, &lifetime.releases);

    line_refusal_poster_t plain = {.line = plain_line};
    line_refusal_poster_t lwip  = {
         .line = unregistered_line, .buf = buf, .with_buffer = true, .bind_out_of_range = true};
    configureRaceSeam(0, kWorkerMessageEnqueueBeforeLifetimeLock);

    wthread_t plain_thread;
    wthread_t unregistered_thread;
    require(threadCreate(&plain_thread, lineRefusalPosterRoutine, &plain) == kWThreadErrorNone,
            "failed to create plain line-refusal poster");
    require(threadCreate(&unregistered_thread, lineRefusalPosterRoutine, &lwip) == kWThreadErrorNone,
            "failed to create out-of-range line-refusal poster");
    waitForEnqueueSeamHits(2, "line-refusal posters did not both retain their lines before detach");

    require(atomicLoadU32Relaxed(&plain_line->refc) == 2 && atomicLoadU32Relaxed(&unregistered_line->refc) == 2,
            "line-refusal posters did not hold exactly one scheduling reference");
    lineDestroy(plain_line);
    lineDestroy(unregistered_line);
    require(! lineIsAlive(plain_line) && ! lineIsAlive(unregistered_line),
            "owner destruction did not make both refused-task lines logically dead");

    teardownCurrentWorker(getWorker(0));
    atomicStoreExplicit(&g_enqueue_seam_release, true, memory_order_release);
    require(threadJoin(plain_thread) == 0, "failed to join plain line-refusal poster");
    require(threadJoin(unregistered_thread) == 0, "failed to join out-of-range line-refusal poster");
    clearRaceSeam();

    require(plain.result == kLineTaskSubmitRejectedSettled && lwip.result == kLineTaskSubmitRejectedSettled,
            "post-detach line scheduling did not report settled rejection");
    require(atomicLoadRelaxed(&lifetime.releases) == 1,
            "refused buffered task did not destroy its standalone buffer exactly once");
    require(genericpoolGetInUse(pool) == 0, "foreign final line release left checked-out pool items");
    require(genericpoolGetInUse(other_pool) == 0,
            "cross-local-pool line migration corrupted family-wide outstanding accounting");
    require(atomicLoadExplicit(&master->len, memory_order_acquire) == 2,
            "plain/out-of-range final releases did not return exactly two lines through the shared master pool");

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

void testTeardownCleanupCannotReadmitMessages(void)
{
    teardown_admission_probe_t probe;
    memoryZero(&probe, sizeof(probe));
    void *late_owner_return   = workerMessagePoolAcquire(sizeof(worker_msg_t));
    void *late_foreign_return = workerMessagePoolAcquire(sizeof(worker_msg_t));

    require(sendWorkerMessageForceQueueWithCleanup(
                0, (WorkerMessageCallback) teardownAdmissionCallback, teardownOuterCleanup, &probe, NULL, NULL),
            "failed to queue teardown admission probe");

    exerciseForeignFinalLineReleaseDuringDetach();

    require(getWorker(0)->message_pool == NULL, "worker teardown retained its message cache");
    const size_t outstanding = masterpoolGetCheckedOut(GSTATE.masterpool_messages);
    workerMessagePoolRelease(late_owner_return);
    wthread_t thread;
    require(threadCreate(&thread, messagePoolForeignRoutine, late_foreign_return) == kWThreadErrorNone,
            "failed to start foreign return after source-worker teardown");
    require(threadJoin(thread) == 0, "failed to join foreign return after source-worker teardown");
    require(masterpoolGetCheckedOut(GSTATE.masterpool_messages) == outstanding - 2,
            "message records did not settle after their source cache was destroyed");

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
