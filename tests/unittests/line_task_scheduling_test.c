/* Focused contract coverage for the four canonical line-task schedulers. */

#include "ev_memory.h"
#include "global_state.h"
#include "master_pool.h"
#include "wloop_internal.h"
#include "worker.h"
#include "worker_messages.h"
#include "wwapi.h"

typedef struct line_task_probe_s
{
    atomic_uint   tasks;
    atomic_uint   cancellations;
    atomic_int    reason;
    atomic_int    callback_wid;
    atomic_uint   callback_refcount;
    atomic_uint   buffer_releases;
    atomic_bool   buffer_was_live_during_cancel;
    atomic_ullong task_time_us;
    uint32_t      expected_cancel_refcount;
    bool          destroy_line_during_cancel;
} line_task_probe_t;

typedef struct tracked_buffer_lifetime_s
{
    sbuf_lifetime_t    base;
    line_task_probe_t *probe;
} tracked_buffer_lifetime_t;

typedef struct line_task_test_env_s
{
    tunnel_chain_t *chain;
    size_t          message_records_baseline;
    uint32_t        timer_count_baseline;
} line_task_test_env_t;

typedef struct line_live_gate_s
{
    wmutex_t mutex;
    line_t  *line;
    bool     open;
} line_live_gate_t;

typedef enum foreign_submit_kind_e
{
    kForeignSubmitImmediate = 0,
    kForeignSubmitDelayed,
    kForeignSubmitBufferedImmediate,
    kForeignSubmitBufferedDelayed
} foreign_submit_kind_e;

typedef struct foreign_submit_s
{
    line_live_gate_t         *gate;
    line_task_probe_t        *probe;
    tunnel_t                 *tunnel;
    sbuf_t                   *buf;
    uint32_t                  delay_ms;
    foreign_submit_kind_e     kind;
    line_task_submit_result_e result;
} foreign_submit_t;

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
            "failed to install worker-0 quiescence request");
    workerPerformQuiesce(worker, testShutdownContext());
    require(workerRequestDrain(worker), "failed to request worker-0 drain");
    workerPerformDrain(worker, testShutdownContext());
    require(workerRequestTeardown(worker), "failed to request worker-0 teardown");
    workerPerformTeardown(worker);
}

static void initTestGlobalState(void)
{
    static char            log_off[]         = "OFF";
    ww_construction_data_t init_data         = {0};
    init_data.workers_count                  = 4;
    init_data.ram_profile                    = 4;
    init_data.mtu_size                       = 1500;
    init_data.internal_logger_data.log_level = log_off;
    init_data.core_logger_data.log_level     = log_off;
    init_data.network_logger_data.log_level  = log_off;
    init_data.dns_logger_data.log_level      = log_off;

    require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create line-task fixture global state");
}

static void shutdownTestGlobalState(void)
{
    for (wid_t wid = 1; wid < getWorkersCount(); ++wid)
    {
        require(workerExitJoin(getWorker(wid)), "failed to stop a line-task fixture worker");
    }

    if (! atomicLoadExplicit(&getWorker(0)->resources_destroyed, memory_order_relaxed))
    {
        teardownCurrentWorker(getWorker(0));
    }
    workerDestroyPseudoWorkerResources(getWorker(getTotalWorkersCount() - 1));
    destroyGlobalState();
}

static void lineTaskEnvSetup(line_task_test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    initTestGlobalState();
    env->chain = tunnelchainCreate(getWorkersCount());
    require(env->chain != NULL, "failed to create line-task test chain");
    tunnelchainFinalize(env->chain);
    require(env->chain->finalized, "failed to finalize line-task test chain");
    env->message_records_baseline = masterpoolGetCheckedOut(GSTATE.masterpool_messages);
    env->timer_count_baseline     = wloopNTimers(getWorkerLoop(0));
}

static void lineTaskEnvTeardown(line_task_test_env_t *env)
{
    require(masterpoolGetCheckedOut(GSTATE.masterpool_messages) == env->message_records_baseline,
            "line-task fixture retained a pooled scheduling record");
    require(wloopNTimers(getWorkerLoop(0)) == env->timer_count_baseline, "line-task fixture retained an event timer");
    tunnelchainDestroy(env->chain);
    env->chain = NULL;
    shutdownTestGlobalState();
}

static line_t *createLine(const line_task_test_env_t *env, wid_t wid)
{
    return wid == 0 ? lineCreate(tunnelchainGetLinePools(env->chain), 0)
                    : lineCreateForWorker(0, tunnelchainGetLinePools(env->chain), wid);
}

static void probeReset(line_task_probe_t *probe)
{
    memoryZero(probe, sizeof(*probe));
    atomic_init(&probe->tasks, 0);
    atomic_init(&probe->cancellations, 0);
    atomic_init(&probe->reason, -1);
    atomic_init(&probe->callback_wid, -2);
    atomic_init(&probe->callback_refcount, 0);
    atomic_init(&probe->buffer_releases, 0);
    atomic_init(&probe->buffer_was_live_during_cancel, false);
    atomic_init(&probe->task_time_us, 0);
    probe->expected_cancel_refcount = 2;
}

static tunnel_t *probeTunnelCreate(line_task_probe_t *probe)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(line_task_probe_t *), 0);
    require(t != NULL, "failed to create line-task probe tunnel");
    *(line_task_probe_t **) tunnelGetState(t) = probe;
    return t;
}

static void trackedBufferRetain(sbuf_lifetime_t *base)
{
    discard base;
    require(false, "line-task test unexpectedly cloned a tracked buffer");
}

static void trackedBufferRelease(sbuf_lifetime_t *base)
{
    tracked_buffer_lifetime_t *lifetime = (tracked_buffer_lifetime_t *) base;
    atomicAddExplicit(&lifetime->probe->buffer_releases, 1, memory_order_relaxed);
}

static sbuf_t *createTrackedBuffer(line_task_probe_t *probe, tracked_buffer_lifetime_t *lifetime)
{
    *lifetime = (tracked_buffer_lifetime_t) {
        .base  = {.retain = trackedBufferRetain, .release = trackedBufferRelease},
        .probe = probe,
    };

    sbuf_t *buf = sbufCreate(64);
    require(buf != NULL, "failed to allocate a tracked line-task buffer");
    sbufSetLength(buf, 16);
    sbufAttachLifetime(buf, &lifetime->base);
    return buf;
}

static sbuf_t *createTrackedPooledBuffer(line_t *line, line_task_probe_t *probe, tracked_buffer_lifetime_t *lifetime)
{
    *lifetime = (tracked_buffer_lifetime_t) {
        .base  = {.retain = trackedBufferRetain, .release = trackedBufferRelease},
        .probe = probe,
    };

    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(buf, 16);
    sbufAttachLifetime(buf, &lifetime->base);
    return buf;
}

static sbuf_t *reacquireTrackedPooledBuffer(line_t *line, sbuf_t *expected)
{
    buffer_pool_t *pool           = lineGetBufferPool(line);
    const bool     use_large_tier = bufferpoolGetSmallBufferSize(pool) == bufferpoolGetLargeBufferSize(pool) &&
                                bufferpoolGetSmallBufferPadding(pool) == bufferpoolGetLargeBufferPadding(pool);
    sbuf_t *intervening[64];
    size_t  intervening_count = 0;

    while (intervening_count < ARRAY_SIZE(intervening))
    {
        sbuf_t *candidate = use_large_tier ? bufferpoolGetLargeBuffer(pool) : bufferpoolGetSmallBuffer(pool);
        if (candidate == expected)
        {
            while (intervening_count > 0)
            {
                bufferpoolReuseBuffer(pool, intervening[--intervening_count]);
            }
            return candidate;
        }
        intervening[intervening_count++] = candidate;
    }

    require(false, "owner-pool buffer was not available for pointer-identical reacquisition");
    return NULL;
}

static line_task_probe_t *taskProbe(tunnel_t *t)
{
    require(t != NULL, "line-task callback received no probe tunnel");
    return *(line_task_probe_t **) tunnelGetState(t);
}

static void probeTask(tunnel_t *t, line_t *line)
{
    line_task_probe_t *probe = taskProbe(t);
    require(lineIsOnCurrentEventWorker(line), "line task ran outside its owner worker");
    atomicStoreExplicit(&probe->callback_wid, (int) lineGetWID(line), memory_order_relaxed);
    atomicStoreExplicit(&probe->task_time_us, wloopNowUS(getWorkerLoop(lineGetWID(line))), memory_order_relaxed);
    atomicAddExplicit(&probe->tasks, 1, memory_order_release);
}

static void probeTaskWithBuf(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    probeTask(t, line);
    sbufDestroy(buf);
}

static void probeCancellation(tunnel_t *t, line_t *line, line_task_cancel_reason_e reason)
{
    line_task_probe_t *probe = taskProbe(t);

    atomicStoreExplicit(&probe->reason, (int) reason, memory_order_relaxed);
    atomicStoreExplicit(&probe->callback_wid, workerWIDForLog(getWID()), memory_order_relaxed);
    atomicStoreExplicit(&probe->callback_refcount, atomicLoadRelaxed(&line->refc), memory_order_relaxed);
    atomicStoreExplicit(
        &probe->buffer_was_live_during_cancel, atomicLoadRelaxed(&probe->buffer_releases) == 0, memory_order_relaxed);
    atomicAddExplicit(&probe->cancellations, 1, memory_order_release);

    if (probe->destroy_line_during_cancel && lineIsAlive(line))
    {
        lineDestroy(line);
    }
}

static unsigned int probeTerminalCount(const line_task_probe_t *probe)
{
    return (unsigned int) atomicLoadExplicit((atomic_uint *) &probe->tasks, memory_order_acquire) +
           (unsigned int) atomicLoadExplicit((atomic_uint *) &probe->cancellations, memory_order_acquire);
}

static void pumpOwnerUntilTerminal(line_task_probe_t *probe, const char *message)
{
    for (uint32_t attempt = 0; attempt < 5000U; ++attempt)
    {
        discard wloopProcessEvents(getWorkerLoop(0), 0);
        if (probeTerminalCount(probe) == 1)
        {
            return;
        }
        wwSleepMS(1);
    }
    require(false, message);
}

static void requireTaskDisposition(const line_task_probe_t *probe, const char *message)
{
    require(probeTerminalCount(probe) == 1, message);
    require(atomicLoadRelaxed((atomic_uint *) &probe->tasks) == 1, "task did not execute exactly once");
    require(atomicLoadRelaxed((atomic_uint *) &probe->cancellations) == 0, "successful task also ran cancellation");
    require(atomicLoadRelaxed((atomic_int *) &probe->callback_wid) == 0, "task ran on the wrong worker");
}

static void requireCancelDisposition(const line_task_probe_t *probe, line_task_cancel_reason_e reason,
                                     const char *message)
{
    require(probeTerminalCount(probe) == 1, message);
    require(atomicLoadRelaxed((atomic_uint *) &probe->tasks) == 0, "cancelled task still executed");
    require(atomicLoadRelaxed((atomic_uint *) &probe->cancellations) == 1, "cancellation did not execute exactly once");
    require(atomicLoadRelaxed((atomic_int *) &probe->reason) == (int) reason, "cancellation reason was imprecise");
    require(atomicLoadRelaxed((atomic_uint *) &probe->callback_refcount) == probe->expected_cancel_refcount,
            "cancellation did not retain exactly the expected scheduler line reference");
}

static void requirePoolBaseline(const line_task_test_env_t *env, const char *message)
{
    require(masterpoolGetCheckedOut(GSTATE.masterpool_messages) == env->message_records_baseline, message);
    if (getWorker(0)->loop != NULL)
    {
        require(wloopNTimers(getWorker(0)->loop) == env->timer_count_baseline,
                "line-task settlement retained an event timer");
    }
}

static void liveGateInit(line_live_gate_t *gate, line_t *line)
{
    mutexInit(&gate->mutex);
    gate->line = line;
    gate->open = true;
}

static void liveGateDestroy(line_live_gate_t *gate)
{
    mutexLock(&gate->mutex);
    gate->open   = false;
    line_t *line = gate->line;
    gate->line   = NULL;
    if (line != NULL && lineIsAlive(line))
    {
        lineDestroy(line);
    }
    mutexUnlock(&gate->mutex);
    mutexDestroy(&gate->mutex);
}

static WTHREAD_ROUTINE(foreignSubmitRoutine)
{
    foreign_submit_t *submission = userdata;
    require(getWID() == kInvalidWID, "foreign line-task submitter inherited a worker identity");

    mutexLock(&submission->gate->mutex);
    require(submission->gate->open && submission->gate->line != NULL && lineIsAlive(submission->gate->line),
            "foreign submitter did not hold a synchronized live-line gate");
    line_t *line = submission->gate->line;
    lineRef(line);

    if (submission->kind == kForeignSubmitBufferedDelayed)
    {
        submission->result = lineScheduleDelayedTaskWithBuf(
            line, probeTaskWithBuf, submission->delay_ms, submission->tunnel, submission->buf, probeCancellation);
    }
    else if (submission->kind == kForeignSubmitDelayed)
    {
        submission->result =
            lineScheduleDelayedTask(line, probeTask, submission->delay_ms, submission->tunnel, probeCancellation);
    }
    else if (submission->kind == kForeignSubmitBufferedImmediate)
    {
        submission->result =
            lineScheduleTaskWithBuf(line, probeTaskWithBuf, submission->tunnel, submission->buf, probeCancellation);
    }
    else
    {
        submission->result = lineScheduleTask(line, probeTask, submission->tunnel, probeCancellation);
    }

    lineUnref(line);
    mutexUnlock(&submission->gate->mutex);
    return 0;
}

void workerMessageEnqueueTestSeam(worker_t *worker, worker_message_enqueue_test_stage_e stage)
{
    discard worker;
    discard stage;
}

void workerMessageTimedRearmTestSeam(worker_t *worker, uint64_t *deadline_us)
{
    discard worker;
    discard deadline_us;
}

static void testSuccessfulSubmissions(line_task_test_env_t *env)
{
    line_task_probe_t probe;
    line_t           *line;
    tunnel_t         *probe_tunnel = probeTunnelCreate(&probe);

    probeReset(&probe);
    line = createLine(env, 0);
    require(lineScheduleTask(line, probeTask, probe_tunnel, probeCancellation) == kLineTaskSubmitAcceptedAsync,
            "owner immediate task did not report AcceptedAsync");
    require(probeTerminalCount(&probe) == 0, "owner immediate task executed inline");
    pumpOwnerUntilTerminal(&probe, "owner immediate task did not execute");
    requireTaskDisposition(&probe, "owner immediate task violated task XOR cancellation");
    lineDestroy(line);
    requirePoolBaseline(env, "owner immediate task leaked a scheduling record");

    probeReset(&probe);
    tracked_buffer_lifetime_t success_lifetime;
    sbuf_t                   *success_buf = createTrackedBuffer(&probe, &success_lifetime);
    line                                  = createLine(env, 0);
    require(lineScheduleTaskWithBuf(line, probeTaskWithBuf, probe_tunnel, success_buf, probeCancellation) ==
                kLineTaskSubmitAcceptedAsync,
            "owner buffered task did not report AcceptedAsync");
    pumpOwnerUntilTerminal(&probe, "owner buffered task did not execute");
    requireTaskDisposition(&probe, "owner buffered task violated task XOR cancellation");
    require(atomicLoadRelaxed(&probe.buffer_releases) == 1,
            "executed buffered task did not take and settle ownership exactly once");
    lineDestroy(line);
    requirePoolBaseline(env, "owner buffered task leaked a scheduling record");

    probeReset(&probe);
    line = createLine(env, 0);
    require(lineScheduleDelayedTask(line, probeTask, 0, probe_tunnel, probeCancellation) ==
                kLineTaskSubmitAcceptedAsync,
            "owner delayed-zero task did not report AcceptedAsync");
    require(probeTerminalCount(&probe) == 0, "delayed-zero task executed inline");
    pumpOwnerUntilTerminal(&probe, "delayed-zero task did not run on a later iteration");
    requireTaskDisposition(&probe, "delayed-zero task violated task XOR cancellation");
    lineDestroy(line);
    requirePoolBaseline(env, "delayed-zero task leaked a scheduling record");

    probeReset(&probe);
    line                 = createLine(env, 0);
    const uint32_t delay = 10;
    const uint64_t start = wloopNowUS(getWorkerLoop(0));
    require(lineScheduleDelayedTask(line, probeTask, delay, probe_tunnel, probeCancellation) ==
                kLineTaskSubmitTimerArmed,
            "owner positive delay did not report TimerArmed");
    discard wloopProcessEvents(getWorkerLoop(0), 0);
    require(probeTerminalCount(&probe) == 0, "positive-delay task ran before its minimum delay");
    pumpOwnerUntilTerminal(&probe, "owner positive-delay task did not execute");
    requireTaskDisposition(&probe, "owner positive-delay task violated task XOR cancellation");
    require(atomicLoadRelaxed(&probe.task_time_us) >= start + ((uint64_t) delay * 1000ULL),
            "positive-delay task ran before its true deadline");
    lineDestroy(line);
    requirePoolBaseline(env, "owner positive-delay task leaked pooled records");

    probeReset(&probe);
    line_live_gate_t gate;
    line = createLine(env, 0);
    liveGateInit(&gate, line);
    foreign_submit_t submission = {
        .gate   = &gate,
        .probe  = &probe,
        .tunnel = probe_tunnel,
        .kind   = kForeignSubmitImmediate,
    };
    wthread_t poster;
    require(threadCreate(&poster, foreignSubmitRoutine, &submission) == kWThreadErrorNone,
            "failed to start foreign immediate submitter");
    require(threadJoin(poster) == 0, "failed to join foreign immediate submitter");
    require(submission.result == kLineTaskSubmitAcceptedAsync, "foreign immediate task did not report AcceptedAsync");
    pumpOwnerUntilTerminal(&probe, "foreign immediate task did not execute");
    requireTaskDisposition(&probe, "foreign immediate task violated task XOR cancellation");
    liveGateDestroy(&gate);
    requirePoolBaseline(env, "foreign immediate task leaked a scheduling record");

    probeReset(&probe);
    line = createLine(env, 0);
    liveGateInit(&gate, line);
    submission = (foreign_submit_t) {
        .gate     = &gate,
        .probe    = &probe,
        .tunnel   = probe_tunnel,
        .delay_ms = 5,
        .kind     = kForeignSubmitDelayed,
    };
    require(threadCreate(&poster, foreignSubmitRoutine, &submission) == kWThreadErrorNone,
            "failed to start foreign delayed submitter");
    require(threadJoin(poster) == 0, "failed to join foreign delayed submitter");
    require(submission.result == kLineTaskSubmitAcceptedAsync,
            "foreign delayed task falsely claimed a synchronously armed timer");
    pumpOwnerUntilTerminal(&probe, "foreign delayed task did not execute");
    requireTaskDisposition(&probe, "foreign delayed task violated task XOR cancellation");
    liveGateDestroy(&gate);
    requirePoolBaseline(env, "foreign delayed task leaked pooled records");
    tunnelDestroy(probe_tunnel);
}

static void testSynchronousRefusals(line_task_test_env_t *env)
{
    line_task_probe_t probe;
    tunnel_t         *probe_tunnel = probeTunnelCreate(&probe);

    probeReset(&probe);
    line_t *line = createLine(env, kInvalidWID);
    require(lineScheduleTask(line, probeTask, probe_tunnel, probeCancellation) == kLineTaskSubmitRejectedSettled,
            "unavailable target did not report RejectedSettled");
    requireCancelDisposition(
        &probe, kLineTaskCancelTargetUnavailable, "unavailable target violated task XOR cancellation");
    lineDestroy(line);
    requirePoolBaseline(env, "unavailable-target refusal leaked a scheduling record");

    probeReset(&probe);
    line = createLine(env, 1);
    workerMessagesCloseAdmission(getWorker(1));
    require(lineScheduleTask(line, probeTask, probe_tunnel, probeCancellation) == kLineTaskSubmitRejectedSettled,
            "closed admission did not report RejectedSettled");
    requireCancelDisposition(&probe, kLineTaskCancelAdmissionClosed, "closed admission violated task XOR cancellation");
    lineDestroy(line);
    requirePoolBaseline(env, "admission refusal leaked a scheduling record");

    const worker_message_enqueue_test_failure_e failures[] = {
        kWorkerMessageEnqueueFailDequeGrowth,
        kWorkerMessageEnqueueFailWakeupPost,
    };
    for (size_t i = 0; i < ARRAY_SIZE(failures); ++i)
    {
        probeReset(&probe);
        line = createLine(env, 0);
        workerMessagesEnqueueTestSetFailure(failures[i]);
        require(lineScheduleTask(line, probeTask, probe_tunnel, probeCancellation) == kLineTaskSubmitRejectedSettled,
                "enqueue failure did not report RejectedSettled");
        requireCancelDisposition(
            &probe, kLineTaskCancelEnqueueFailure, "enqueue failure violated task XOR cancellation");
        lineDestroy(line);
        requirePoolBaseline(env, "enqueue refusal leaked a scheduling record");
    }
    tunnelDestroy(probe_tunnel);
}

static void testTimerResourceFailures(line_task_test_env_t *env)
{
    line_task_probe_t probe;
    line_t           *line;
    tunnel_t         *probe_tunnel = probeTunnelCreate(&probe);

    probeReset(&probe);
    line = createLine(env, 0);
    eventloopTestFailNextTryZalloc();
    require(lineScheduleDelayedTask(line, probeTask, 25, probe_tunnel, probeCancellation) ==
                kLineTaskSubmitRejectedSettled,
            "owner timer allocation failure did not report RejectedSettled");
    requireCancelDisposition(
        &probe, kLineTaskCancelResourceFailure, "owner timer failure violated task XOR cancellation");
    lineDestroy(line);
    requirePoolBaseline(env, "owner timer failure leaked pooled records");

    probeReset(&probe);
    tracked_buffer_lifetime_t owner_lifetime;
    line        = createLine(env, 0);
    sbuf_t *buf = createTrackedPooledBuffer(line, &probe, &owner_lifetime);
    eventloopTestFailNextTryZalloc();
    require(lineScheduleDelayedTaskWithBuf(line, probeTaskWithBuf, 25, probe_tunnel, buf, probeCancellation) ==
                kLineTaskSubmitRejectedSettled,
            "buffered owner timer allocation failure did not report RejectedSettled");
    requireCancelDisposition(
        &probe, kLineTaskCancelResourceFailure, "buffered owner failure violated task XOR cancellation");
    require(atomicLoadRelaxed(&probe.buffer_was_live_during_cancel), "buffer settled before cancellation notification");
    require(atomicLoadRelaxed(&probe.buffer_releases) == 1, "owner cancellation did not settle buffer exactly once");
    sbuf_t *reacquired = reacquireTrackedPooledBuffer(line, buf);
    require(reacquired == buf, "owner cancellation destroyed its pooled buffer instead of recycling it");
    lineReuseBuffer(line, reacquired);
    lineDestroy(line);
    requirePoolBaseline(env, "buffered owner timer failure leaked pooled records");

    probeReset(&probe);
    line_live_gate_t gate;
    line = createLine(env, 0);
    liveGateInit(&gate, line);
    foreign_submit_t submission = {
        .gate     = &gate,
        .probe    = &probe,
        .tunnel   = probe_tunnel,
        .delay_ms = 25,
        .kind     = kForeignSubmitDelayed,
    };
    wthread_t poster;
    eventloopTestFailNextTryZalloc();
    require(threadCreate(&poster, foreignSubmitRoutine, &submission) == kWThreadErrorNone,
            "failed to start foreign timer-failure submitter");
    require(threadJoin(poster) == 0, "failed to join foreign timer-failure submitter");
    require(submission.result == kLineTaskSubmitAcceptedAsync,
            "foreign timer setup was not reported as asynchronous admission");
    pumpOwnerUntilTerminal(&probe, "foreign owner-side timer failure did not cancel");
    requireCancelDisposition(
        &probe, kLineTaskCancelResourceFailure, "foreign timer failure violated task XOR cancellation");
    require(atomicLoadRelaxed(&probe.callback_wid) == 0,
            "foreign timer failure cancellation did not run on the owner worker");
    liveGateDestroy(&gate);
    requirePoolBaseline(env, "foreign timer failure leaked pooled records");

    probeReset(&probe);
    tracked_buffer_lifetime_t foreign_lifetime;
    line                = createLine(env, 0);
    sbuf_t *foreign_buf = createTrackedPooledBuffer(line, &probe, &foreign_lifetime);
    liveGateInit(&gate, line);
    submission = (foreign_submit_t) {
        .gate     = &gate,
        .probe    = &probe,
        .tunnel   = probe_tunnel,
        .buf      = foreign_buf,
        .delay_ms = 25,
        .kind     = kForeignSubmitBufferedDelayed,
    };
    eventloopTestFailNextTryZalloc();
    require(threadCreate(&poster, foreignSubmitRoutine, &submission) == kWThreadErrorNone,
            "failed to start foreign buffered timer-failure submitter");
    require(threadJoin(poster) == 0, "failed to join foreign buffered timer-failure submitter");
    require(submission.result == kLineTaskSubmitAcceptedAsync,
            "foreign buffered timer setup was not reported as asynchronous admission");
    pumpOwnerUntilTerminal(&probe, "foreign buffered owner-side timer failure did not cancel");
    requireCancelDisposition(
        &probe, kLineTaskCancelResourceFailure, "foreign buffered timer failure violated task XOR cancellation");
    require(atomicLoadRelaxed(&probe.callback_wid) == 0,
            "foreign buffered timer failure cancellation did not run on the owner worker");
    require(atomicLoadRelaxed(&probe.buffer_was_live_during_cancel),
            "foreign delayed buffer settled before cancellation notification");
    require(atomicLoadRelaxed(&probe.buffer_releases) == 1,
            "foreign delayed cancellation did not settle its buffer exactly once");
    reacquired = reacquireTrackedPooledBuffer(line, foreign_buf);
    require(reacquired == foreign_buf, "foreign delayed cancellation did not recycle the buffer on the owner worker");
    lineReuseBuffer(line, reacquired);
    liveGateDestroy(&gate);
    requirePoolBaseline(env, "foreign buffered timer failure leaked pooled records");

    line = createLine(env, 0);
    for (uint32_t attempt = 0; attempt < 32U; ++attempt)
    {
        probeReset(&probe);
        eventloopTestFailNextTryZalloc();
        require(lineScheduleDelayedTask(line, probeTask, 25, probe_tunnel, probeCancellation) ==
                    kLineTaskSubmitRejectedSettled,
                "repeated timer allocation failure was not settled synchronously");
        requireCancelDisposition(
            &probe, kLineTaskCancelResourceFailure, "repeated timer allocation failure lost terminal settlement");
        requirePoolBaseline(env, "repeated timer allocation failure leaked or corrupted scheduler state");
    }

    probeReset(&probe);
    require(lineScheduleDelayedTask(line, probeTask, 2, probe_tunnel, probeCancellation) == kLineTaskSubmitTimerArmed,
            "timer heap did not accept work after repeated injected failures");
    pumpOwnerUntilTerminal(&probe, "post-failure timer did not execute");
    requireTaskDisposition(&probe, "post-failure timer violated task XOR cancellation");
    requirePoolBaseline(env, "post-failure timer retained scheduler state");
    lineDestroy(line);
    tunnelDestroy(probe_tunnel);
}

static void testLineDeathNullAndBufferedSettlement(line_task_test_env_t *env)
{
    line_task_probe_t probe;
    line_t           *line;
    tunnel_t         *probe_tunnel = probeTunnelCreate(&probe);

    probeReset(&probe);
    line = createLine(env, 0);
    lineRef(line);
    require(lineScheduleTask(line, probeTask, probe_tunnel, probeCancellation) == kLineTaskSubmitAcceptedAsync,
            "line-death immediate task was not admitted");
    lineDestroy(line);
    pumpOwnerUntilTerminal(&probe, "dead immediate line did not cancel its task");
    requireCancelDisposition(&probe, kLineTaskCancelLineDead, "dead immediate line violated task XOR cancellation");
    lineUnref(line);
    requirePoolBaseline(env, "dead immediate task leaked a scheduling record");

    probeReset(&probe);
    line = createLine(env, 0);
    lineRef(line);
    require(lineScheduleDelayedTask(line, probeTask, 5, probe_tunnel, probeCancellation) == kLineTaskSubmitTimerArmed,
            "line-death delayed task was not armed");
    lineDestroy(line);
    pumpOwnerUntilTerminal(&probe, "dead delayed line did not cancel its task");
    requireCancelDisposition(&probe, kLineTaskCancelLineDead, "dead delayed line violated task XOR cancellation");
    lineUnref(line);
    requirePoolBaseline(env, "dead delayed task leaked pooled records");

    probeReset(&probe);
    tracked_buffer_lifetime_t dead_immediate_lifetime;
    line                   = createLine(env, 0);
    sbuf_t *dead_immediate = createTrackedPooledBuffer(line, &probe, &dead_immediate_lifetime);
    lineRef(line);
    require(lineScheduleTaskWithBuf(line, probeTaskWithBuf, probe_tunnel, dead_immediate, probeCancellation) ==
                kLineTaskSubmitAcceptedAsync,
            "buffered immediate line-death task was not admitted");
    lineDestroy(line);
    pumpOwnerUntilTerminal(&probe, "dead buffered immediate line did not cancel its task");
    requireCancelDisposition(
        &probe, kLineTaskCancelLineDead, "dead buffered immediate line violated task XOR cancellation");
    require(atomicLoadRelaxed(&probe.buffer_was_live_during_cancel),
            "dead buffered immediate task released its buffer before notification");
    require(atomicLoadRelaxed(&probe.buffer_releases) == 1,
            "dead buffered immediate task did not release its buffer exactly once");
    sbuf_t *reacquired = reacquireTrackedPooledBuffer(line, dead_immediate);
    require(reacquired == dead_immediate, "dead buffered immediate task did not recycle its owner-pool buffer");
    lineReuseBuffer(line, reacquired);
    lineUnref(line);
    requirePoolBaseline(env, "dead buffered immediate task leaked scheduler state");

    probeReset(&probe);
    tracked_buffer_lifetime_t dead_delayed_lifetime;
    line                 = createLine(env, 0);
    sbuf_t *dead_delayed = createTrackedPooledBuffer(line, &probe, &dead_delayed_lifetime);
    lineRef(line);
    require(lineScheduleDelayedTaskWithBuf(line, probeTaskWithBuf, 5, probe_tunnel, dead_delayed, probeCancellation) ==
                kLineTaskSubmitTimerArmed,
            "buffered delayed line-death task was not armed");
    lineDestroy(line);
    pumpOwnerUntilTerminal(&probe, "dead buffered delayed line did not cancel its task");
    requireCancelDisposition(
        &probe, kLineTaskCancelLineDead, "dead buffered delayed line violated task XOR cancellation");
    require(atomicLoadRelaxed(&probe.buffer_was_live_during_cancel),
            "dead buffered delayed task released its buffer before notification");
    require(atomicLoadRelaxed(&probe.buffer_releases) == 1,
            "dead buffered delayed task did not release its buffer exactly once");
    reacquired = reacquireTrackedPooledBuffer(line, dead_delayed);
    require(reacquired == dead_delayed, "dead buffered delayed task did not recycle its owner-pool buffer");
    lineReuseBuffer(line, reacquired);
    lineUnref(line);
    requirePoolBaseline(env, "dead buffered delayed task leaked scheduler state");

    probeReset(&probe);
    tracked_buffer_lifetime_t null_lifetime;
    sbuf_t                   *null_buf = createTrackedBuffer(&probe, &null_lifetime);
    line                               = createLine(env, kInvalidWID);
    require(lineScheduleTaskWithBuf(line, probeTaskWithBuf, probe_tunnel, null_buf, NULL) ==
                kLineTaskSubmitRejectedSettled,
            "NULL-cancellation buffered refusal did not report RejectedSettled");
    require(atomicLoadRelaxed(&probe.tasks) == 0 && atomicLoadRelaxed(&probe.cancellations) == 0,
            "NULL cancellation unexpectedly notified user code");
    require(atomicLoadRelaxed(&probe.buffer_releases) == 1,
            "NULL-cancellation path did not settle its buffer exactly once");
    lineDestroy(line);
    requirePoolBaseline(env, "NULL-cancellation buffered refusal leaked a scheduling record");

    probeReset(&probe);
    probe.expected_cancel_refcount = 3;
    tracked_buffer_lifetime_t foreign_lifetime;
    sbuf_t                   *foreign_buf = createTrackedBuffer(&probe, &foreign_lifetime);
    line                                  = createLine(env, kInvalidWID);
    line_live_gate_t gate;
    liveGateInit(&gate, line);
    foreign_submit_t submission = {
        .gate   = &gate,
        .probe  = &probe,
        .tunnel = probe_tunnel,
        .buf    = foreign_buf,
        .kind   = kForeignSubmitBufferedImmediate,
    };
    wthread_t poster;
    require(threadCreate(&poster, foreignSubmitRoutine, &submission) == kWThreadErrorNone,
            "failed to start foreign buffered-refusal submitter");
    require(threadJoin(poster) == 0, "failed to join foreign buffered-refusal submitter");
    require(submission.result == kLineTaskSubmitRejectedSettled,
            "foreign buffered refusal did not report RejectedSettled");
    requireCancelDisposition(
        &probe, kLineTaskCancelTargetUnavailable, "foreign buffered refusal violated task XOR cancellation");
    require(atomicLoadRelaxed(&probe.buffer_was_live_during_cancel),
            "foreign buffer settled before cancellation notification");
    require(atomicLoadRelaxed(&probe.buffer_releases) == 1,
            "foreign cancellation did not destroy its buffer exactly once");
    liveGateDestroy(&gate);
    requirePoolBaseline(env, "foreign buffered refusal leaked a scheduling record");

    probeReset(&probe);
    probe.expected_cancel_refcount   = 3;
    probe.destroy_line_during_cancel = true;
    line                             = createLine(env, kInvalidWID);
    lineRef(line);
    require(lineScheduleTask(line, probeTask, probe_tunnel, probeCancellation) == kLineTaskSubmitRejectedSettled,
            "re-entrant cancellation did not report RejectedSettled");
    requireCancelDisposition(
        &probe, kLineTaskCancelTargetUnavailable, "re-entrant cancellation violated task XOR cancellation");
    require(! lineIsAlive(line), "re-entrant cancellation did not destroy the line");
    lineUnref(line);
    requirePoolBaseline(env, "re-entrant cancellation leaked a scheduling record");

    probeReset(&probe);
    probe.expected_cancel_refcount   = 3;
    probe.destroy_line_during_cancel = true;
    tracked_buffer_lifetime_t reentrant_lifetime;
    line                  = createLine(env, 0);
    sbuf_t *reentrant_buf = createTrackedPooledBuffer(line, &probe, &reentrant_lifetime);
    lineRef(line);
    eventloopTestFailNextTryZalloc();
    require(
        lineScheduleDelayedTaskWithBuf(line, probeTaskWithBuf, 25, probe_tunnel, reentrant_buf, probeCancellation) ==
            kLineTaskSubmitRejectedSettled,
        "buffered re-entrant cancellation was not settled synchronously");
    requireCancelDisposition(
        &probe, kLineTaskCancelResourceFailure, "buffered re-entrant cancellation violated task XOR cancellation");
    require(! lineIsAlive(line), "buffered re-entrant cancellation did not destroy the live line");
    require(atomicLoadRelaxed(&probe.buffer_was_live_during_cancel),
            "buffered re-entrant cancellation released the buffer before notification");
    require(atomicLoadRelaxed(&probe.buffer_releases) == 1,
            "buffered re-entrant cancellation did not settle its buffer exactly once");
    reacquired = reacquireTrackedPooledBuffer(line, reentrant_buf);
    require(reacquired == reentrant_buf, "buffered re-entrant cancellation did not recycle the owner buffer");
    lineReuseBuffer(line, reacquired);
    lineUnref(line);
    requirePoolBaseline(env, "buffered re-entrant cancellation leaked scheduler state");
    tunnelDestroy(probe_tunnel);
}

static void testQuiescenceSettlement(void)
{
    line_task_test_env_t env;
    lineTaskEnvSetup(&env);

    line_task_probe_t queued_probe;
    line_task_probe_t armed_probe;
    line_task_probe_t buffered_probe;
    probeReset(&queued_probe);
    probeReset(&armed_probe);
    probeReset(&buffered_probe);
    tunnel_t *queued_tunnel   = probeTunnelCreate(&queued_probe);
    tunnel_t *armed_tunnel    = probeTunnelCreate(&armed_probe);
    tunnel_t *buffered_tunnel = probeTunnelCreate(&buffered_probe);

    line_t          *queued_line   = createLine(&env, 0);
    line_t          *armed_line    = createLine(&env, 0);
    line_t          *buffered_line = createLine(&env, 0);
    line_live_gate_t gate;
    liveGateInit(&gate, queued_line);

    foreign_submit_t submission = {
        .gate     = &gate,
        .probe    = &queued_probe,
        .tunnel   = queued_tunnel,
        .delay_ms = 60000,
        .kind     = kForeignSubmitDelayed,
    };
    wthread_t poster;
    require(threadCreate(&poster, foreignSubmitRoutine, &submission) == kWThreadErrorNone,
            "failed to start pre-quiescence foreign submitter");
    require(threadJoin(poster) == 0, "failed to join pre-quiescence foreign submitter");
    require(submission.result == kLineTaskSubmitAcceptedAsync,
            "pre-quiescence foreign setup was not accepted asynchronously");

    require(lineScheduleDelayedTask(armed_line, probeTask, 60000, armed_tunnel, probeCancellation) ==
                kLineTaskSubmitTimerArmed,
            "pre-quiescence owner timer was not armed");

    tracked_buffer_lifetime_t buffered_lifetime;
    sbuf_t *buffered_buf = createTrackedPooledBuffer(buffered_line, &buffered_probe, &buffered_lifetime);
    require(lineScheduleDelayedTaskWithBuf(
                buffered_line, probeTaskWithBuf, 60000, buffered_tunnel, buffered_buf, probeCancellation) ==
                kLineTaskSubmitTimerArmed,
            "pre-quiescence buffered owner timer was not armed");

    worker_t *worker = getWorker(0);
    require(workerInstallApplicationQuiesceRequest(worker, testShutdownContext()) != kWorkerQuiesceRequestUnavailable,
            "failed to request line-task quiescence");
    workerPerformQuiesce(worker, testShutdownContext());

    requireCancelDisposition(
        &queued_probe, kLineTaskCancelQuiesced, "queued timer setup was not cancelled by quiescence");
    requireCancelDisposition(&armed_probe, kLineTaskCancelQuiesced, "armed timer was not cancelled by quiescence");
    requireCancelDisposition(
        &buffered_probe, kLineTaskCancelQuiesced, "buffered armed timer was not cancelled by quiescence");
    require(atomicLoadRelaxed(&buffered_probe.buffer_was_live_during_cancel),
            "quiescence released the buffered timer payload before notification");
    require(atomicLoadRelaxed(&buffered_probe.buffer_releases) == 1,
            "quiescence did not settle the buffered timer payload exactly once");
    sbuf_t *reacquired = reacquireTrackedPooledBuffer(buffered_line, buffered_buf);
    require(reacquired == buffered_buf, "quiescence did not recycle the buffered timer payload to its owner pool");
    lineReuseBuffer(buffered_line, reacquired);
    require(masterpoolGetCheckedOut(GSTATE.masterpool_messages) == env.message_records_baseline,
            "quiescence cancellation leaked pooled records");
    require(wloopNTimers(getWorkerLoop(0)) == 0, "quiescence retained a scheduler or component timer after settlement");

    liveGateDestroy(&gate);
    lineDestroy(armed_line);
    lineDestroy(buffered_line);
    tunnelDestroy(buffered_tunnel);
    tunnelDestroy(armed_tunnel);
    tunnelDestroy(queued_tunnel);
    tunnelchainDestroy(env.chain);
    env.chain = NULL;
    shutdownTestGlobalState();
}

static void testTeardownSettlement(void)
{
    line_task_test_env_t env;
    lineTaskEnvSetup(&env);

    line_task_probe_t probe;
    line_task_probe_t buffered_probe;
    probeReset(&probe);
    probeReset(&buffered_probe);
    tunnel_t *probe_tunnel    = probeTunnelCreate(&probe);
    tunnel_t *buffered_tunnel = probeTunnelCreate(&buffered_probe);
    line_t   *line            = createLine(&env, 0);
    line_t   *buffered_line   = createLine(&env, 0);
    require(lineScheduleTask(line, probeTask, probe_tunnel, probeCancellation) == kLineTaskSubmitAcceptedAsync,
            "teardown task was not admitted");

    tracked_buffer_lifetime_t buffered_lifetime;
    sbuf_t *buffered_buf = createTrackedPooledBuffer(buffered_line, &buffered_probe, &buffered_lifetime);
    require(
        lineScheduleTaskWithBuf(buffered_line, probeTaskWithBuf, buffered_tunnel, buffered_buf, probeCancellation) ==
            kLineTaskSubmitAcceptedAsync,
        "buffered teardown task was not admitted");

    worker_t               *worker = getWorker(0);
    wloop_t                *loop   = NULL;
    worker_message_queue_t *queue  = NULL;
    workerMessagesCloseAdmissionAndDetach(worker, &loop, &queue);
    workerMessagesCleanupPendingDetached(queue, kWorkerMessageCancelTeardown);

    requireCancelDisposition(
        &probe, kLineTaskCancelTeardown, "detached queue teardown did not report precise cancellation");
    requireCancelDisposition(
        &buffered_probe, kLineTaskCancelTeardown, "buffered detached queue teardown reported imprecise cancellation");
    require(atomicLoadRelaxed(&buffered_probe.buffer_was_live_during_cancel),
            "detached queue teardown released the buffer before notification");
    require(atomicLoadRelaxed(&buffered_probe.buffer_releases) == 1,
            "detached queue teardown did not settle the buffer exactly once");
    sbuf_t *reacquired = reacquireTrackedPooledBuffer(buffered_line, buffered_buf);
    require(reacquired == buffered_buf, "detached queue teardown did not recycle the buffer to its owner pool");
    lineReuseBuffer(buffered_line, reacquired);

    /* Restore the now-empty resources so ordinary fixture teardown can own and
     * destroy them through the production path. */
    mutexLock(&worker->control_mutex);
    require(worker->loop == NULL && worker->message_queue == NULL,
            "worker resources were republished during detached teardown");
    worker->loop          = loop;
    worker->message_queue = queue;
    mutexUnlock(&worker->control_mutex);

    requirePoolBaseline(&env, "teardown cancellation leaked a scheduling record");

    lineDestroy(line);
    lineDestroy(buffered_line);
    tunnelDestroy(buffered_tunnel);
    tunnelDestroy(probe_tunnel);
    tunnelchainDestroy(env.chain);
    env.chain = NULL;
    shutdownTestGlobalState();
}

static void testTimerInstallAdmissionBoundary(void)
{
    line_task_test_env_t env;
    lineTaskEnvSetup(&env);

    line_task_probe_t probe;
    probeReset(&probe);
    tunnel_t *probe_tunnel = probeTunnelCreate(&probe);
    line_t   *line         = createLine(&env, 0);

    workerMessagesTimerInstallTestCloseAdmission();
    require(lineScheduleDelayedTask(line, probeTask, 25, probe_tunnel, probeCancellation) ==
                kLineTaskSubmitRejectedSettled,
            "timer-boundary admission closure did not settle the owner submission synchronously");
    requireCancelDisposition(
        &probe, kLineTaskCancelAdmissionClosed, "timer-boundary admission closure was mislabeled as resource failure");
    requirePoolBaseline(&env, "timer-boundary admission closure retained scheduler state");

    lineDestroy(line);
    tunnelDestroy(probe_tunnel);
    lineTaskEnvTeardown(&env);
}

static void unexpectedPendingTimerCallback(wtimer_t *timer)
{
    discard timer;
    require(false, "raw loop destruction dispatched a pending timer callback");
}

static void testPendingTryTimerLoopDestruction(void)
{
    const long outstanding_before = eventloopAllocCount() - eventloopFreeCount();
    wloop_t   *loop               = wloopCreate(0, NULL, 0);
    wtimer_t  *pending_timer      = NULL;
    wtimer_t  *heap_timer         = NULL;

    require(wtimerTryAdd(loop, unexpectedPendingTimerCallback, 60000, 1, &pending_timer) == kWTimerTryAddInstalled,
            "failed to install the raw-loop pending timer fixture");
    require(wtimerTryAdd(loop, unexpectedPendingTimerCallback, 60000, 1, &heap_timer) == kWTimerTryAddInstalled,
            "failed to install the raw-loop heap timer fixture");
    wtimerTestMakePendingOneShot(pending_timer);
    require(wloopNTimers(loop) == 1, "pending one-shot fixture corrupted the remaining timer heap");

    wloopDestroy(&loop);
    require(loop == NULL, "raw loop destruction did not consume the loop");
    require(eventloopAllocCount() - eventloopFreeCount() == outstanding_before,
            "raw loop destruction leaked or mismatched the pending try-timer allocation");
}

int main(void)
{
    line_task_test_env_t env;
    lineTaskEnvSetup(&env);

    testSuccessfulSubmissions(&env);
    testSynchronousRefusals(&env);
    testTimerResourceFailures(&env);
    testLineDeathNullAndBufferedSettlement(&env);

    lineTaskEnvTeardown(&env);

    testQuiescenceSettlement();
    testTeardownSettlement();
    testTimerInstallAdmissionBoundary();
    testPendingTryTimerLoopDestruction();

    puts("line_task_scheduling_test: all cases passed");
    return 0;
}
