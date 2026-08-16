/*
 * Process shutdown manager: orderly off-main shutdown requests.
 *
 * Every successful case exits the process, so each scenario runs in a forked
 * child that reports back over an inherited pipe. The child builds a real global
 * state with several workers, arranges for a chosen worker to call
 * requestProgramShutdown(), and lets runMainThread() drive the normal shutdown.
 *
 * What is being pinned:
 *   - late exit observers run exactly once on the main thread, after workers
 *     and lwIP have stopped but before process-lifetime control state is freed;
 *   - a non-zero worker can request shutdown, return, and still be joined;
 *   - exit-code arbitration is deterministic (first non-zero wins);
 *   - duplicate requests coalesce instead of forcing an immediate _Exit();
 *   - a requester really unwinds before worker 0 needs its locks;
 *   - a request that cannot be handed off reports failure to its caller.
 */

#include "wloop_internal.h"
#include "wwapi.h"

#include <sys/wait.h>
#include <unistd.h>

enum
{
    kReportMagic     = 0x5744574DU, // "WDWM"
    kTestWorkerCount = 4,
    kWaitTimeoutMs   = 15000
};

/* One record per shutdown-callback invocation, so duplicates are visible. */
typedef struct
{
    uint32_t magic;
    uint64_t callback_tid;
    uint64_t main_tid;
    uint8_t  requesters_unwound;
    uint8_t  probe_mutex_acquired;
    uint8_t  handoff_reported_failure;
    uint8_t  workers_stopped;
    uint8_t  lwip_stopped;
    uint8_t  spontaneous_failure_context;
    uint8_t  spontaneous_failure_admission_closed;
    uint8_t  spontaneous_failure_reason;
} shutdown_report_t;

typedef enum
{
    kScenarioWorkerSuccess = 0,
    kScenarioWorkerError,
    kScenarioTwoWorkers,
    kScenarioErrorThenSuccess,
    kScenarioSuccessThenError,
    kScenarioSuccessThenPreservedError,
    kScenarioProbeMutex,
    kScenarioWorkerZero,
    kScenarioDuplicateRequests,
    kScenarioSpontaneousWorkerFailure
} scenario_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

// ---------------------------------------------------------------------------
// Child-side state
// ---------------------------------------------------------------------------

static int         child_report_fd = -1;
static scenario_t  child_scenario;
static atomic_int  requesters_ready;
static atomic_int  requesters_unwound;
static atomic_bool requesters_released;
static atomic_bool first_request_done;
static atomic_bool second_request_done;
static wmutex_t    probe_mutex;
static uint8_t     probe_mutex_acquired;
static uint8_t     unwind_target;
static wthread_t   poster_thread;
static bool        poster_thread_valid;

static bool waitForBool(atomic_bool *flag, unsigned int timeout_ms)
{
    for (unsigned int waited = 0; waited < timeout_ms; waited += 5)
    {
        if (atomicLoadExplicit(flag, memory_order_acquire))
        {
            return true;
        }
        wwSleepMS(5);
    }
    return atomicLoadExplicit(flag, memory_order_acquire);
}

static bool waitForCount(atomic_int *counter, uint8_t target, unsigned int timeout_ms)
{
    for (unsigned int waited = 0; waited < timeout_ms; waited += 5)
    {
        if (atomicLoadExplicit(counter, memory_order_acquire) >= (w_atomic_int_value_t) target)
        {
            return true;
        }
        wwSleepMS(5);
    }
    return atomicLoadExplicit(counter, memory_order_acquire) >= (w_atomic_int_value_t) target;
}

/* Late non-owning observer; all component and worker shutdown has completed. */
static void reportingExitCallback(void *userdata, int signum)
{
    discard userdata;
    discard signum;

    if (child_scenario == kScenarioProbeMutex)
    {
        // The worker join preceding this observer could not complete until the
        // requester returned and released the mutex.
        mutexLock(&probe_mutex);
        probe_mutex_acquired = 1;
        mutexUnlock(&probe_mutex);
    }

    if (child_scenario == kScenarioErrorThenSuccess || child_scenario == kScenarioSuccessThenError ||
        child_scenario == kScenarioSuccessThenPreservedError)
    {
        // Hold the sequence here until both requests have been issued, so the
        // arbitration result does not depend on how fast the process exits.
        discard waitForBool(&second_request_done, kWaitTimeoutMs);
    }

    /*
     * Wait (bounded) for every requester in this scenario to return from
     * requestProgramShutdown(). Sampling the counter immediately would only
     * record whichever requesters happened to be scheduled before worker 0
     * reached this callback, which is a race, not a property.
     *
     * The workers were joined before this observer, so the counter must already
     * be complete. The bounded wait keeps a useful diagnostic if a broken join
     * path reaches the observer anyway.
     */
    const bool all_unwound = waitForCount(&requesters_unwound, unwind_target, kWaitTimeoutMs);

    shutdown_report_t report        = {0};
    report.magic                    = kReportMagic;
    report.callback_tid             = (uint64_t) getTID();
    report.main_tid                 = GSTATE.main_thread_id;
    report.requesters_unwound       = (uint8_t) all_unwound;
    report.probe_mutex_acquired     = probe_mutex_acquired;
    report.handoff_reported_failure = 0;
    report.lwip_stopped             = (uint8_t) ! GSTATE.flag_lwip_initialized;
    report.workers_stopped          = 1;
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        if (workerGetLifecycle(getWorker(wid)) < kWorkerLifecycleExited)
        {
            report.workers_stopped = 0;
            break;
        }
    }
    if (child_scenario == kScenarioSpontaneousWorkerFailure)
    {
        worker_t *failed_worker = getWorker(1);
        report.spontaneous_failure_context =
            (uint8_t) (failed_worker->lifecycle_context_set &&
                       failed_worker->lifecycle_context.scope == kWwLifecycleProcessShutdown);
        report.spontaneous_failure_admission_closed =
            (uint8_t) ! atomicLoadRelaxed(&failed_worker->message_admission_open);
        report.spontaneous_failure_reason =
            (uint8_t) (applicationShutdownGetReason() == kApplicationShutdownReasonWorkerFailure);
    }

    ssize_t written = write(child_report_fd, &report, sizeof(report));
    discard written;
}

static void noteUnwound(void)
{
    discard atomicIncExplicit(&requesters_unwound, memory_order_acq_rel);
}

static void synchronizeRequesters(void)
{
    discard atomicIncExplicit(&requesters_ready, memory_order_acq_rel);
    require(waitForCount(&requesters_ready, unwind_target, kWaitTimeoutMs),
            "not every shutdown requester entered its callback");
}

/*
 * Runs on the target worker's event loop.
 *
 * Both request callbacks are posted before either is allowed to proceed, then
 * released together. Without that gate the first worker's request could start
 * (and finish) the whole shutdown before the second worker's callback even ran,
 * which is not the concurrent case this scenario is meant to cover.
 */
static void firstRequestEventCB(wevent_t *ev)
{
    discard ev;

    discard waitForBool(&requesters_released, kWaitTimeoutMs);
    synchronizeRequesters();

    switch (child_scenario)
    {
    case kScenarioWorkerError:
        require(requestProgramShutdown(1), "worker request with a non-zero status was not accepted");
        break;

    case kScenarioProbeMutex:
        mutexLock(&probe_mutex);
        require(requestProgramShutdown(0), "worker request was not accepted while holding the probe mutex");
        // Keep the mutex a little longer than worker 0 needs to reach the
        // callback, so acquiring it there proves this thread was free to unwind.
        wwSleepMS(100);
        mutexUnlock(&probe_mutex);
        break;

    case kScenarioDuplicateRequests:
        require(requestProgramShutdown(0), "the first duplicate request was not accepted");
        require(requestProgramShutdown(0), "the coalesced duplicate request was rejected");
        require(requestProgramShutdown(0), "a third duplicate request was rejected");
        break;

    case kScenarioErrorThenSuccess:
        require(requestProgramShutdown(1), "the error request was not accepted");
        break;

    case kScenarioSuccessThenError:
    case kScenarioSuccessThenPreservedError:
        require(requestProgramShutdown(0), "the success request was not accepted");
        break;

    case kScenarioWorkerSuccess:
    case kScenarioTwoWorkers:
    case kScenarioWorkerZero:
    default:
        require(requestProgramShutdown(0), "worker request with a zero status was not accepted");
        break;
    }

    noteUnwound();
    atomicStoreExplicit(&first_request_done, true, memory_order_release);
}

/* Runs on a second worker; ordered after the first request where it matters. */
static void secondRequestEventCB(wevent_t *ev)
{
    discard ev;

    discard waitForBool(&requesters_released, kWaitTimeoutMs);
    synchronizeRequesters();

    switch (child_scenario)
    {
    case kScenarioErrorThenSuccess:
        discard waitForBool(&first_request_done, kWaitTimeoutMs);
        // A later zero must not overwrite the recorded error.
        require(requestProgramShutdown(0), "the trailing success request was rejected");
        break;

    case kScenarioSuccessThenError:
        discard waitForBool(&first_request_done, kWaitTimeoutMs);
        // A later non-zero must still win over the initial zero.
        require(requestProgramShutdown(1), "the trailing error request was rejected");
        break;

    case kScenarioSuccessThenPreservedError:
        discard waitForBool(&first_request_done, kWaitTimeoutMs);
        require(signalmanagerRequestShutdownPreservingAcceptedStatus(1),
                "the status-preserving trailing request was rejected");
        break;

    case kScenarioTwoWorkers:
    default:
        require(requestProgramShutdown(0), "the concurrent request was rejected");
        break;
    }

    noteUnwound();
    atomicStoreExplicit(&second_request_done, true, memory_order_release);
}

static void spontaneousWorkerFailureEventCB(wevent_t *ev)
{
    discard ev;
    noteUnwound();
}

typedef struct
{
    wid_t     wid;
    wevent_cb cb;
} post_request_t;

static post_request_t posts[2];
static uint8_t        posts_count;

/*
 * Helper thread: waits until the target loops are actually running, then posts
 * the request callbacks. Posting after wloopRun() started means the loops own
 * their wakeup descriptors, so nothing is created cross-thread here.
 */
static WTHREAD_ROUTINE(requestPosterMain) // NOLINT
{
    discard userdata;

    for (uint8_t i = 0; i < posts_count; ++i)
    {
        wloop_t *loop = getWorkerLoop(posts[i].wid);

        for (unsigned int waited = 0; waited < kWaitTimeoutMs; waited += 5)
        {
            if (wloopStatus(loop) == WLOOP_STATUS_RUNNING)
            {
                break;
            }
            wwSleepMS(5);
        }

        wevent_t ev;
        memoryZero(&ev, sizeof(ev));
        ev.loop = loop;
        ev.cb   = posts[i].cb;
        weventSetPriority(&ev, WEVENT_HIGH_PRIORITY);

        if (! wloopPostEvent(loop, &ev))
        {
            const char *msg     = "FAIL: could not post the shutdown request onto the target worker\n";
            ssize_t     written = write(STDERR_FILENO, msg, strlen(msg));
            discard     written;
            _Exit(70);
        }
    }

    // Every request callback is queued now; release them together so the
    // concurrent scenarios really do overlap.
    atomicStoreExplicit(&requesters_released, true, memory_order_release);
    return 0;
}

static void joinPosterThread(void)
{
    if (poster_thread_valid)
    {
        require(safeThreadJoin(poster_thread), "failed to join the shutdown-request poster");
        poster_thread_valid = false;
    }
}

static char child_log_level[] = "FATAL";

_Noreturn static void runChild(scenario_t scenario, int report_fd)
{
    child_scenario  = scenario;
    child_report_fd = report_fd;
    mutexInit(&probe_mutex);

    ww_construction_data_t init_data = {0};
    init_data.workers_count          = kTestWorkerCount;
    init_data.ram_profile            = kRamProfileS1Memory;
    init_data.mtu_size               = 1500;
    init_data.application_finalizer  = joinPosterThread;

    init_data.internal_logger_data.log_level = child_log_level;
    init_data.core_logger_data.log_level     = child_log_level;
    init_data.network_logger_data.log_level  = child_log_level;
    init_data.dns_logger_data.log_level      = child_log_level;

    require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create shutdown-manager fixture");

    // Exit observers are late and non-owning; the coordinator runs them after
    // worker/lwIP shutdown and before destroying process-lifetime state.
    registerAtExitCallBack(reportingExitCallback, NULL);

    switch (scenario)
    {
    case kScenarioTwoWorkers:
    case kScenarioErrorThenSuccess:
    case kScenarioSuccessThenError:
    case kScenarioSuccessThenPreservedError:
        unwind_target = 2;
        posts_count   = 2;
        posts[0].wid  = 1;
        posts[0].cb   = firstRequestEventCB;
        posts[1].wid  = 2;
        posts[1].cb   = secondRequestEventCB;
        break;

    case kScenarioWorkerZero:
        unwind_target = 1;
        posts_count   = 1;
        posts[0].wid  = 0;
        posts[0].cb   = firstRequestEventCB;
        break;

    case kScenarioSpontaneousWorkerFailure:
        getWorkerLoop(1)->flags |= WLOOP_FLAG_RUN_ONCE;
        unwind_target = 1;
        posts_count   = 1;
        posts[0].wid  = 1;
        posts[0].cb   = spontaneousWorkerFailureEventCB;
        break;

    default:
        unwind_target = 1;
        posts_count   = 1;
        posts[0].wid  = 1;
        posts[0].cb   = firstRequestEventCB;
        break;
    }

    if (threadCreate(&poster_thread, requestPosterMain, NULL) != kWThreadErrorNone)
    {
        _Exit(71);
    }
    poster_thread_valid = true;

    runMainThread();
    _Exit(72); // runMainThread() must not return
}

// ---------------------------------------------------------------------------
// Parent-side driver
// ---------------------------------------------------------------------------

typedef struct
{
    unsigned int      record_count;
    shutdown_report_t first;
    int               exit_status;
    bool              exited_normally;
} scenario_result_t;

static scenario_result_t runScenario(scenario_t scenario)
{
    int report_pipe[2];
    require(pipe(report_pipe) == 0, "failed to create the shutdown report pipe");

    pid_t child = fork();
    require(child >= 0, "failed to fork the shutdown scenario child");

    if (child == 0)
    {
        discard close(report_pipe[0]);
        runChild(scenario, report_pipe[1]);
    }

    discard close(report_pipe[1]);

    scenario_result_t result = {0};
    shutdown_report_t record;

    for (;;)
    {
        ssize_t got = read(report_pipe[0], &record, sizeof(record));
        if (got == 0)
        {
            break;
        }
        if (got < 0)
        {
            break;
        }
        require(got == (ssize_t) sizeof(record), "received a truncated shutdown report record");
        require(record.magic == kReportMagic, "received a corrupted shutdown report record");
        if (result.record_count == 0)
        {
            result.first = record;
        }
        result.record_count++;
    }
    discard close(report_pipe[0]);

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for the shutdown scenario child");
    result.exited_normally = WIFEXITED(status);
    result.exit_status     = result.exited_normally ? WEXITSTATUS(status) : -1;
    return result;
}

static void checkCommonInvariants(const scenario_result_t *result, const char *label)
{
    char message[256];

    snprintf(message, sizeof(message), "%s: the child did not exit normally", label);
    require(result->exited_normally, message);

    snprintf(message,
             sizeof(message),
             "%s: shutdown callbacks ran %u times instead of exactly once",
             label,
             result->record_count);
    require(result->record_count == 1, message);

    snprintf(message, sizeof(message), "%s: the shutdown callback did not run on the main thread", label);
    require(result->first.callback_tid == result->first.main_tid, message);

    snprintf(message, sizeof(message), "%s: a shutdown requester did not unwind before cleanup ran", label);
    require(result->first.requesters_unwound == 1, message);

    snprintf(message, sizeof(message), "%s: an exit observer ran before every event worker stopped", label);
    require(result->first.workers_stopped == 1, message);

    snprintf(message, sizeof(message), "%s: an exit observer ran before lwIP stopped", label);
    require(result->first.lwip_stopped == 1, message);
}

static void expectExitStatus(const scenario_result_t *result, int expected, const char *label)
{
    char message[256];
    snprintf(message, sizeof(message), "%s: exit status was %d instead of %d", label, result->exit_status, expected);
    require(result->exit_status == expected, message);
}

/* Runs a child with no worker-0 handoff available and returns its exit status. */
static int runHandoffFailureChild(bool request_error_first, int fallback_code)
{
    pid_t child = fork();
    require(child >= 0, "failed to fork the handoff failure child");

    if (child == 0)
    {
        GSTATE                = (ww_global_state_t) {0};
        GSTATE.main_thread_id = (uint64_t) getTID();

        // The controller and signal manager exist, but signalmanagerStart()
        // never created a control transport to worker 0.
        GSTATE.application_shutdown = applicationShutdownCreate();
        GSTATE.signal_manager       = signalmanagerCreate();

        if (requestProgramShutdown(request_error_first ? 1 : 0))
        {
            _Exit(80); // must not claim success without a handoff
        }
        // A failed request must not leave a phase behind that makes the next
        // request coalesce into a shutdown nobody will ever execute.
        if (requestProgramShutdown(0))
        {
            _Exit(81);
        }

        abortProgramNow(fallback_code);
    }

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for the handoff failure child");
    require(WIFEXITED(status), "the handoff failure child did not exit normally");
    return WEXITSTATUS(status);
}

/*
 * requestProgramShutdown() must report failure - not silently pretend success -
 * when no worker-0 handoff exists yet, and the documented fallback is a hard
 * abort carrying the arbitrated exit code.
 */
static void testHandoffFailure(void)
{
    // Nothing was recorded before the fallback, so the fallback code is used.
    require(runHandoffFailureChild(false, 3) == 3, "the handoff failure fallback used the wrong exit status");

    // Rejection occurs before publication, so an unavailable controller does
    // not retain status from a request it never accepted.
    require(runHandoffFailureChild(true, 0) == 0, "an unavailable request published an exit status");
}

typedef struct finalization_race_s
{
    atomic_bool                     start;
    application_shutdown_snapshot_t snapshot;
    bool                            finalized;
} finalization_race_t;

typedef struct request_race_s
{
    atomic_bool                          *start;
    application_shutdown_reason_e         reason;
    application_shutdown_request_result_e result;
} request_race_t;

typedef struct publication_race_s
{
    atomic_bool                           paused;
    atomic_bool                           release;
    atomic_bool                           second_entered;
    atomic_bool                           second_returned;
    application_shutdown_request_result_e first_result;
    application_shutdown_request_result_e second_result;
} publication_race_t;

typedef struct commit_request_race_s
{
    atomic_bool                           start;
    bool                                  commit_result;
    application_shutdown_request_result_e request_result;
} commit_request_race_t;

static void pauseBeforeRequestPublication(void *userdata)
{
    publication_race_t *race = userdata;
    atomicStoreExplicit(&race->paused, true, memory_order_release);
    while (! atomicLoadExplicit(&race->release, memory_order_acquire))
    {
        YIELD_THREAD();
    }
}

static void *firstPublicationRequester(void *userdata)
{
    publication_race_t *race = userdata;
    race->first_result       = applicationShutdownRequestTyped(0, kApplicationShutdownReasonProgrammatic);
    return NULL;
}

static void *secondPublicationRequester(void *userdata)
{
    publication_race_t *race = userdata;
    atomicStoreExplicit(&race->second_entered, true, memory_order_release);
    race->second_result = applicationShutdownRequestTyped(1, kApplicationShutdownReasonSubsystemFailure);
    atomicStoreExplicit(&race->second_returned, true, memory_order_release);
    return NULL;
}

static void *runtimeCommitRacer(void *userdata)
{
    commit_request_race_t *race = userdata;
    while (! atomicLoadExplicit(&race->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    race->commit_result = applicationShutdownCommitRuntime();
    return NULL;
}

static void *firstRequestRacer(void *userdata)
{
    commit_request_race_t *race = userdata;
    while (! atomicLoadExplicit(&race->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    race->request_result = applicationShutdownRequestTyped(0, kApplicationShutdownReasonProgrammatic);
    return NULL;
}

static void *requestRaceMain(void *userdata)
{
    request_race_t *race = userdata;
    while (! atomicLoadExplicit(race->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    race->result = applicationShutdownRequestTyped(0, race->reason);
    return NULL;
}

static void *lateFailureMain(void *userdata)
{
    finalization_race_t *race = userdata;
    while (! atomicLoadExplicit(&race->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    discard applicationShutdownRequestTyped(7, kApplicationShutdownReasonWorkerFailure);
    return NULL;
}

static void *finalizeMain(void *userdata)
{
    finalization_race_t *race = userdata;
    while (! atomicLoadExplicit(&race->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    race->finalized = applicationShutdownBeginFinalizing(&race->snapshot);
    return NULL;
}

static void testDurableDegradedRequestAndFinalization(void)
{
    worker_t workers[2];
    wloop_t  loop;
    memoryZero(workers, sizeof(workers));
    memoryZero(&loop, sizeof(loop));

    workers[0].wid            = 0;
    workers[0].has_event_loop = true;
    workers[0].loop           = &loop;
    mutexInit(&workers[0].control_mutex);
    condmutexInit(&workers[0].control_condition_mutex);
    condvarInit(&workers[0].control_condition);
    atomic_init(&workers[0].lifecycle, kWorkerLifecycleInitialized);
    atomic_init(&workers[0].message_admission_open, true);

    mutexInit(&loop.normal_admission_mutex);
    mutexInit(&loop.custom_events_mutex);
    atomic_init(&loop.normal_admission_open, true);
    atomic_init(&loop.stop_requested, false);
    loop.eventfds[0] = -2;
    loop.eventfds[1] = -2;

    GSTATE                      = (ww_global_state_t) {0};
    GSTATE.flag_initialized     = true;
    GSTATE.workers              = workers;
    GSTATE.workers_count        = ARRAY_SIZE(workers);
    GSTATE.application_shutdown = applicationShutdownCreate();
    require(GSTATE.application_shutdown != NULL, "failed to create durable-request controller fixture");

    workers[0].loop = NULL;
    require(applicationShutdownRequestTyped(1, kApplicationShutdownReasonSubsystemFailure) ==
                kApplicationShutdownRequestUnavailable,
            "an unavailable worker-0 request was reported as accepted");
    require(applicationShutdownGetPhase() == kApplicationShutdownRunning &&
                applicationShutdownGetReason() == kApplicationShutdownReasonNone &&
                applicationShutdownGetExitCode() == 0,
            "an unavailable worker-0 request mutated the controller");
    ww_lifecycle_context_t selected_context;
    require(! applicationShutdownGetSelectedContext(&selected_context),
            "an unavailable worker-0 request selected a cleanup context");
    workers[0].loop = &loop;

    require(applicationShutdownRequestTyped(0, kApplicationShutdownReasonProgrammatic) ==
                kApplicationShutdownRequestAcceptedWakeDegraded,
            "a degraded wake did not report an accepted durable request");
    require(applicationShutdownGetPhase() == kApplicationShutdownRequested,
            "degraded wake rolled the controller back to Running");
    require(applicationShutdownRequestTyped(0, kApplicationShutdownReasonSignal) ==
                kApplicationShutdownRequestAlreadyAccepted,
            "a repeated request after degraded wake was not idempotent");
    require(applicationShutdownGetReason() == kApplicationShutdownReasonProgrammatic,
            "a repeated request replaced the first accepted reason");
    require(applicationShutdownGetSelectedContext(&selected_context) &&
                selected_context.scope == kWwLifecycleStartupRollback,
            "a pre-commit programmatic request did not select StartupRollback");

    applicationShutdownAdvancePhase(kApplicationShutdownDestroyingWorkers);
    finalization_race_t race;
    memoryZero(&race, sizeof(race));
    atomic_init(&race.start, false);

    pthread_t failure_thread;
    pthread_t finalizer_thread;
    require(pthread_create(&failure_thread, NULL, lateFailureMain, &race) == 0,
            "failed to start late-failure race thread");
    require(pthread_create(&finalizer_thread, NULL, finalizeMain, &race) == 0,
            "failed to start finalization race thread");
    atomicStoreExplicit(&race.start, true, memory_order_release);
    require(pthread_join(failure_thread, NULL) == 0 && pthread_join(finalizer_thread, NULL) == 0,
            "failed to join finalization race threads");

    require(race.finalized, "the legal finalization transition was rejected");
    require(race.snapshot.reason == kApplicationShutdownReasonProgrammatic,
            "finalization changed the primary request reason");
    require(race.snapshot.exit_code == 0 || race.snapshot.exit_code == 7,
            "finalization captured an invalid exit status");
    require(applicationShutdownGetExitCode() == race.snapshot.exit_code,
            "status changed after the finalization snapshot froze it");

    applicationShutdownDestroy();

    atomicStoreRelaxed(&workers[0].lifecycle, kWorkerLifecycleInitialized);
    atomicStoreRelaxed(&workers[0].message_admission_open, true);
    workers[0].lifecycle_context_set = false;
    atomicStoreRelaxed(&loop.normal_admission_open, true);
    atomicStoreRelaxed(&loop.stop_requested, false);
    loop.wakeup_pending         = false;
    GSTATE.application_shutdown = applicationShutdownCreate();
    require(GSTATE.application_shutdown != NULL, "failed to recreate the controller race fixture");
    require(applicationShutdownAcceptSignal(SIGTERM) == kApplicationShutdownRequestAcceptedWakeDegraded,
            "a pre-commit signal request was not accepted");
    require(applicationShutdownGetReason() == kApplicationShutdownReasonSignal,
            "a pre-commit signal changed its diagnostic origin");
    require(applicationShutdownGetSelectedContext(&selected_context) &&
                selected_context.scope == kWwLifecycleStartupRollback,
            "a pre-commit signal did not select StartupRollback");
    applicationShutdownDestroy();

    atomicStoreRelaxed(&workers[0].lifecycle, kWorkerLifecycleInitialized);
    atomicStoreRelaxed(&workers[0].message_admission_open, true);
    workers[0].lifecycle_context_set = false;
    atomicStoreRelaxed(&loop.normal_admission_open, true);
    atomicStoreRelaxed(&loop.stop_requested, false);
    loop.wakeup_pending         = false;
    GSTATE.application_shutdown = applicationShutdownCreate();
    require(GSTATE.application_shutdown != NULL, "failed to recreate the post-commit controller fixture");
    require(applicationShutdownCommitRuntime(), "the controller refused an uncontended runtime commit");

    atomic_bool request_start;
    atomic_init(&request_start, false);
    request_race_t request_races[2] = {
        {.start = &request_start, .reason = kApplicationShutdownReasonProgrammatic},
        {.start = &request_start, .reason = kApplicationShutdownReasonSubsystemFailure},
    };
    pthread_t request_threads[2];
    require(pthread_create(&request_threads[0], NULL, requestRaceMain, &request_races[0]) == 0 &&
                pthread_create(&request_threads[1], NULL, requestRaceMain, &request_races[1]) == 0,
            "failed to start the first-request race threads");
    atomicStoreExplicit(&request_start, true, memory_order_release);
    require(pthread_join(request_threads[0], NULL) == 0 && pthread_join(request_threads[1], NULL) == 0,
            "failed to join the first-request race threads");

    int accepted_index = request_races[0].result == kApplicationShutdownRequestAcceptedWakeDegraded ? 0 : 1;
    int repeated_index = 1 - accepted_index;
    require(request_races[accepted_index].result == kApplicationShutdownRequestAcceptedWakeDegraded,
            "the first raced request did not retain degraded-wake acceptance");
    require(request_races[repeated_index].result == kApplicationShutdownRequestAlreadyAccepted,
            "the second raced request did not coalesce");
    require(applicationShutdownGetReason() == request_races[accepted_index].reason,
            "the raced controller did not preserve the first accepted reason");
    require(applicationShutdownGetSelectedContext(&selected_context) &&
                selected_context.scope == kWwLifecycleProcessShutdown,
            "a post-commit request did not select ProcessShutdown");

    applicationShutdownDestroy();
    atomicStoreRelaxed(&workers[0].lifecycle, kWorkerLifecycleInitialized);
    atomicStoreRelaxed(&workers[0].message_admission_open, true);
    workers[0].lifecycle_context_set = false;
    atomicStoreRelaxed(&loop.normal_admission_open, true);
    atomicStoreRelaxed(&loop.stop_requested, false);
    loop.wakeup_pending         = false;
    GSTATE.application_shutdown = applicationShutdownCreate();
    require(GSTATE.application_shutdown != NULL, "failed to recreate the publication-race controller fixture");

    publication_race_t publication_race;
    memoryZero(&publication_race, sizeof(publication_race));
    atomic_init(&publication_race.paused, false);
    atomic_init(&publication_race.release, false);
    atomic_init(&publication_race.second_entered, false);
    atomic_init(&publication_race.second_returned, false);
    applicationShutdownTestSetBeforePublicationHook(pauseBeforeRequestPublication, &publication_race);

    pthread_t first_publication_thread;
    pthread_t second_publication_thread;
    require(pthread_create(&first_publication_thread, NULL, firstPublicationRequester, &publication_race) == 0,
            "failed to start the first publication requester");
    require(waitForBool(&publication_race.paused, kWaitTimeoutMs),
            "the first publication requester did not reach the transaction seam");
    require(workerGetLifecycle(&workers[0]) == kWorkerLifecycleQuiesceRequested && workers[0].lifecycle_context_set,
            "worker 0 was not installed before request publication");

    require(pthread_create(&second_publication_thread, NULL, secondPublicationRequester, &publication_race) == 0,
            "failed to start the second publication requester");
    require(waitForBool(&publication_race.second_entered, kWaitTimeoutMs),
            "the second publication requester did not enter");
    wwSleepMS(25);
    require(! atomicLoadExplicit(&publication_race.second_returned, memory_order_acquire),
            "a second requester observed acceptance before the first transaction published");

    atomicStoreExplicit(&publication_race.release, true, memory_order_release);
    require(pthread_join(first_publication_thread, NULL) == 0 && pthread_join(second_publication_thread, NULL) == 0,
            "failed to join the publication-race requesters");
    applicationShutdownTestSetBeforePublicationHook(NULL, NULL);
    require(publication_race.first_result == kApplicationShutdownRequestAcceptedWakeDegraded &&
                publication_race.second_result == kApplicationShutdownRequestAlreadyAccepted,
            "the serialized publication race returned invalid request results");

    applicationShutdownDestroy();
    atomicStoreRelaxed(&workers[0].lifecycle, kWorkerLifecycleInitialized);
    atomicStoreRelaxed(&workers[0].message_admission_open, true);
    workers[0].lifecycle_context_set = false;
    atomicStoreRelaxed(&loop.normal_admission_open, true);
    atomicStoreRelaxed(&loop.stop_requested, false);
    loop.wakeup_pending         = false;
    GSTATE.application_shutdown = applicationShutdownCreate();
    require(GSTATE.application_shutdown != NULL, "failed to recreate the commit-race controller fixture");

    commit_request_race_t commit_race;
    memoryZero(&commit_race, sizeof(commit_race));
    atomic_init(&commit_race.start, false);

    pthread_t commit_thread;
    pthread_t request_thread;
    require(pthread_create(&commit_thread, NULL, runtimeCommitRacer, &commit_race) == 0 &&
                pthread_create(&request_thread, NULL, firstRequestRacer, &commit_race) == 0,
            "failed to start the commit/request race threads");
    atomicStoreExplicit(&commit_race.start, true, memory_order_release);
    require(pthread_join(commit_thread, NULL) == 0 && pthread_join(request_thread, NULL) == 0,
            "failed to join the commit/request race threads");
    require(commit_race.request_result == kApplicationShutdownRequestAcceptedWakeDegraded,
            "the commit/request race did not accept its first request");
    require(applicationShutdownGetSelectedContext(&selected_context),
            "the commit/request race did not select a lifecycle context");
    if (commit_race.commit_result)
    {
        require(selected_context.scope == kWwLifecycleProcessShutdown,
                "commit-winning request race did not select ProcessShutdown");
    }
    else
    {
        require(selected_context.scope == kWwLifecycleStartupRollback,
                "request-winning commit race did not select StartupRollback");
    }

    applicationShutdownDestroy();
    contvarDestroy(&workers[0].control_condition);
    condmutexDestroy(&workers[0].control_condition_mutex);
    mutexDestroy(&workers[0].control_mutex);
    mutexDestroy(&loop.normal_admission_mutex);
    mutexDestroy(&loop.custom_events_mutex);
    GSTATE = (ww_global_state_t) {0};
}

int main(void)
{
    scenario_result_t result;

    // 1. A non-zero worker completes successfully.
    result = runScenario(kScenarioWorkerSuccess);
    checkCommonInvariants(&result, "worker success");
    expectExitStatus(&result, 0, "worker success");

    // 2. A non-zero worker reports an error; cleanup still runs.
    result = runScenario(kScenarioWorkerError);
    checkCommonInvariants(&result, "worker error");
    expectExitStatus(&result, 1, "worker error");

    // 3. Two workers request shutdown; cleanup runs once and both unwind.
    result = runScenario(kScenarioTwoWorkers);
    checkCommonInvariants(&result, "two workers");
    require(result.first.requesters_unwound == 1, "not every concurrent requester unwound");
    expectExitStatus(&result, 0, "two workers");

    // 4. An error is recorded first; a later success must not overwrite it.
    result = runScenario(kScenarioErrorThenSuccess);
    checkCommonInvariants(&result, "error then success");
    expectExitStatus(&result, 1, "error then success");

    // 5. A success is recorded first; the error must still win.
    result = runScenario(kScenarioSuccessThenError);
    checkCommonInvariants(&result, "success then error");
    expectExitStatus(&result, 1, "success then error");

    // 6. A terminal reconciliation refusal caused by an accepted shutdown must
    //    not race that success and upgrade its status.
    result = runScenario(kScenarioSuccessThenPreservedError);
    checkCommonInvariants(&result, "success then status-preserving error");
    expectExitStatus(&result, 0, "success then status-preserving error");

    // 7. The requester holds a lock across the request and releases it after
    //    returning; a shutdown callback on worker 0 must be able to take it.
    result = runScenario(kScenarioProbeMutex);
    checkCommonInvariants(&result, "probe mutex");
    require(result.first.probe_mutex_acquired == 1, "the shutdown callback could not acquire the requester's mutex");
    expectExitStatus(&result, 0, "probe mutex");

    // 8. A worker-0 request follows the same once-only state machine and does
    //    not recursively execute callbacks.
    result = runScenario(kScenarioWorkerZero);
    checkCommonInvariants(&result, "worker zero");
    expectExitStatus(&result, 0, "worker zero");

    // 9. Duplicate programmatic requests coalesce instead of forcing an exit.
    result = runScenario(kScenarioDuplicateRequests);
    checkCommonInvariants(&result, "duplicate requests");
    expectExitStatus(&result, 0, "duplicate requests");

    result = runScenario(kScenarioSpontaneousWorkerFailure);
    checkCommonInvariants(&result, "spontaneous worker failure");
    require(result.first.spontaneous_failure_context,
            "spontaneous worker failure did not install ProcessShutdown context");
    require(result.first.spontaneous_failure_admission_closed, "spontaneous worker failure retained message admission");
    require(result.first.spontaneous_failure_reason, "spontaneous worker failure did not select WorkerFailure origin");
    expectExitStatus(&result, 1, "spontaneous worker failure");

    // Handoff failure before worker 0 is available.
    testHandoffFailure();

    testDurableDegradedRequestAndFinalization();

    return 0;
}
