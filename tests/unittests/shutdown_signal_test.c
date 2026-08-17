/*
 * POSIX signal-driven shutdown.
 *
 * Each case runs a forked child that builds a real global state, registers a
 * shutdown callback, and then receives an OS signal. The properties under test:
 *   - a stop signal routes through the same once-only main-thread executor as a
 *     programmatic request, so registered cleanup still runs;
 *   - the callback never executes from the async signal handler's context;
 *   - SIGINT and SIGTERM produce the documented 128 + signum exit status;
 *   - a signal arriving while another worker is busy is still handled;
 *   - a signal that follows a programmatic success request does not overwrite
 *     the already recorded status (first non-zero wins, zero never overwrites);
 *   - a second stop signal forces an immediate exit while cleanup is blocked.
 *   - a full wake pipe still leaves a durable mailbox request for worker 0.
 */

#include "wloop_internal.h"
#include "wwapi.h"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

enum
{
    kReportMagic     = 0x5744534DU, // "WDSM"
    kTestWorkerCount = 3,
    kWaitTimeoutMs   = 15000
};

typedef struct
{
    uint32_t magic;
    uint64_t callback_tid;
    uint64_t main_tid;
    uint8_t  worker_was_busy;
    // The signal manager installs its graceful handlers with every graceful
    // signal in sa_mask, so those signals are blocked for the duration of the
    // async handler and unblocked on the main thread's normal flow. A callback
    // that observes them unblocked therefore cannot be running inside the async
    // handler's context.
    uint8_t stop_signals_blocked;
    uint8_t phase_is_destroying_workers;
} signal_report_t;

typedef enum
{
    kSignalCaseTermIdle = 0,
    kSignalCaseTermBusyWorker,
    kSignalCaseIntStatus,
    kSignalCaseAfterSuccessRequest,
    kSignalCaseFullPipe,
    kSignalCaseSecondSignalForcesExit
} signal_case_t;

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

static int           child_report_fd = -1;
static signal_case_t child_case;
static atomic_bool   worker_is_busy;
static atomic_bool   ready_for_signal;
static atomic_bool   cleanup_entered;
static wthread_t     sender_thread;
static wthread_t     requester_thread;
static bool          sender_thread_valid;
static bool          requester_thread_valid;

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

static void reportingExitCallback(void *userdata, int signum)
{
    discard userdata;
    discard signum;

    atomicStoreExplicit(&cleanup_entered, true, memory_order_release);

    if (child_case == kSignalCaseSecondSignalForcesExit)
    {
        // Deliberately stuck cleanup: only the operator escape hatch (a second
        // stop signal) can end the process from here. Nothing is reported.
        for (;;)
        {
            wwSleepMS(50);
        }
    }

    sigset_t current;
    sigemptyset(&current);
    const bool mask_known = (pthread_sigmask(SIG_BLOCK, NULL, &current) == 0);

    signal_report_t report = {0};
    report.magic           = kReportMagic;
    report.callback_tid    = (uint64_t) getTID();
    report.main_tid        = GSTATE.main_thread_id;
    report.worker_was_busy = (uint8_t) atomicLoadExplicit(&worker_is_busy, memory_order_acquire);
    report.stop_signals_blocked =
        (uint8_t) (mask_known && (sigismember(&current, SIGTERM) == 1 || sigismember(&current, SIGINT) == 1));
    report.phase_is_destroying_workers =
        (uint8_t) (applicationShutdownGetPhase() == kApplicationShutdownDestroyingWorkers);

    ssize_t written = write(child_report_fd, &report, sizeof(report));
    discard written;
}

/* Keeps a non-zero worker occupied while the signal is delivered. */
static void busyWorkerEventCB(wevent_t *ev)
{
    discard ev;

    atomicStoreExplicit(&worker_is_busy, true, memory_order_release);
    atomicStoreExplicit(&ready_for_signal, true, memory_order_release);

    // Busy for long enough that the signal certainly lands while this worker is
    // still inside its callback.
    wwSleepMS(400);
}

static atomic_bool signal_was_raised;

/*
 * Runs on worker 0 and keeps it out of its poll loop until both control bytes
 * (the programmatic request marker and the signal number) are sitting in the
 * shutdown self-pipe. Worker 0 then drains the whole batch in one read, which is
 * what makes the arbitration result deterministic rather than a scheduling race.
 */
static void worker0BusyEventCB(wevent_t *ev)
{
    discard ev;

    atomicStoreExplicit(&ready_for_signal, true, memory_order_release);
    discard waitForBool(&signal_was_raised, kWaitTimeoutMs);
    // Small settle so the signal handler's pipe write has certainly landed.
    wwSleepMS(50);
}

/*
 * Issues the programmatic success request while worker 0 is still busy. The
 * signal that follows records 128 + signum, and a zero can never overwrite it.
 */
static WTHREAD_ROUTINE(successRequestMain) // NOLINT
{
    discard userdata;

    discard waitForBool(&ready_for_signal, kWaitTimeoutMs);
    if (! requestProgramShutdown(0))
    {
        _Exit(80);
    }
    atomicStoreExplicit(&worker_is_busy, true, memory_order_release);
    return 0;
}

static void joinSignalHelperThreads(void)
{
    if (sender_thread_valid)
    {
        require(safeThreadJoin(sender_thread), "failed to join the signal-sender thread");
        sender_thread_valid = false;
    }
    if (requester_thread_valid)
    {
        require(safeThreadJoin(requester_thread), "failed to join the success-request thread");
        requester_thread_valid = false;
    }
}

typedef struct
{
    wid_t     wid;
    wevent_cb cb;
    int       signal_to_raise;
    bool      raise_twice;
} child_plan_t;

static child_plan_t child_plan;

static bool postPlannedEventWhenWorkerLoopRuns(void)
{
    worker_t *worker = getWorker(child_plan.wid);

    for (unsigned int waited = 0; waited < kWaitTimeoutMs; waited += 5)
    {
        bool attempted = false;
        bool posted    = false;

        /* Keep the non-owning loop pointer alive through the foreign post. */
        mutexLock(&worker->control_mutex);
        wloop_t *loop = worker->loop;
        if (loop != NULL && wloopStatus(loop) == WLOOP_STATUS_RUNNING)
        {
            wevent_t ev;
            memoryZero(&ev, sizeof(ev));
            ev.loop = loop;
            ev.cb   = child_plan.cb;
            weventSetPriority(&ev, WEVENT_HIGH_PRIORITY);

            attempted = true;
            posted    = wloopPostEvent(loop, &ev);
        }
        const bool loop_available = loop != NULL;
        mutexUnlock(&worker->control_mutex);

        if (attempted)
        {
            return posted;
        }
        if (! loop_available)
        {
            return false;
        }
        wwSleepMS(5);
    }

    return false;
}

static bool waitForWorkerLoopToRun(wid_t wid)
{
    worker_t *worker = getWorker(wid);

    for (unsigned int waited = 0; waited < kWaitTimeoutMs; waited += 5)
    {
        mutexLock(&worker->control_mutex);
        wloop_t   *loop           = worker->loop;
        const bool loop_available = loop != NULL;
        const bool running        = loop_available && wloopStatus(loop) == WLOOP_STATUS_RUNNING;
        mutexUnlock(&worker->control_mutex);

        if (running)
        {
            return true;
        }
        if (! loop_available)
        {
            return false;
        }
        wwSleepMS(5);
    }

    return false;
}

static void fillShutdownWakePipe(void)
{
    unsigned char bytes[512] = {0};
    int           fd         = signalmanagerGet()->shutdown_pipe[1];
    for (;;)
    {
        ssize_t result = write(fd, bytes, sizeof(bytes));
        if (result > 0)
        {
            continue;
        }
        require(result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
                "failed to fill the shutdown wake pipe deterministically");
        return;
    }
}

/*
 * Helper thread: waits for the scenario to be ready, then sends the signal to
 * the process. Signals are blocked on every spawned thread, so the kernel
 * delivers it to the main thread - which is the mask policy under test.
 */
static WTHREAD_ROUTINE(signalSenderMain) // NOLINT
{
    discard userdata;

    if (child_plan.cb != NULL)
    {
        if (! postPlannedEventWhenWorkerLoopRuns())
        {
            _Exit(81);
        }

        discard waitForBool(&ready_for_signal, kWaitTimeoutMs);

        if (child_case == kSignalCaseAfterSuccessRequest)
        {
            // The programmatic request must be in the pipe before the signal is.
            discard waitForBool(&worker_is_busy, kWaitTimeoutMs);
        }
    }
    else
    {
        // Idle case: let worker 0 settle into its poll first.
        if (! waitForWorkerLoopToRun(0))
        {
            _Exit(85);
        }
        wwSleepMS(100);
    }

    discard kill(getpid(), child_plan.signal_to_raise);
    atomicStoreExplicit(&signal_was_raised, true, memory_order_release);

    if (child_plan.raise_twice)
    {
        // Wait until cleanup is genuinely stuck, then use the escape hatch.
        discard waitForBool(&cleanup_entered, kWaitTimeoutMs);
        wwSleepMS(100);
        discard kill(getpid(), child_plan.signal_to_raise);
    }

    return 0;
}

static char child_log_level[] = "FATAL";

_Noreturn static void runChild(signal_case_t scenario, int report_fd)
{
    child_case      = scenario;
    child_report_fd = report_fd;

    ww_construction_data_t init_data = {0};
    init_data.workers_count          = kTestWorkerCount;
    init_data.ram_profile            = kRamProfileS1Memory;
    init_data.mtu_size               = 1500;
    init_data.application_finalizer  = joinSignalHelperThreads;

    init_data.internal_logger_data.log_level = child_log_level;
    init_data.core_logger_data.log_level     = child_log_level;
    init_data.network_logger_data.log_level  = child_log_level;
    init_data.dns_logger_data.log_level      = child_log_level;

    require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create shutdown-signal fixture");
    registerAtExitCallBack(reportingExitCallback, NULL);

    switch (scenario)
    {
    case kSignalCaseTermBusyWorker:
        child_plan = (child_plan_t) {.wid = 1, .cb = busyWorkerEventCB, .signal_to_raise = SIGTERM};
        break;
    case kSignalCaseIntStatus:
        child_plan = (child_plan_t) {.signal_to_raise = SIGINT};
        break;
    case kSignalCaseAfterSuccessRequest:
        // Worker 0 is held busy while a separate thread issues the programmatic
        // request, so the signal that follows lands in the same control batch.
        child_plan = (child_plan_t) {.wid = 0, .cb = worker0BusyEventCB, .signal_to_raise = SIGTERM};
        break;
    case kSignalCaseSecondSignalForcesExit:
        child_plan = (child_plan_t) {.signal_to_raise = SIGTERM, .raise_twice = true};
        break;
    case kSignalCaseFullPipe:
        fillShutdownWakePipe();
        child_plan = (child_plan_t) {.signal_to_raise = SIGTERM};
        break;
    case kSignalCaseTermIdle:
    default:
        child_plan = (child_plan_t) {.signal_to_raise = SIGTERM};
        break;
    }

    if (scenario == kSignalCaseAfterSuccessRequest)
    {
        if (threadCreate(&requester_thread, successRequestMain, NULL) != kWThreadErrorNone)
        {
            _Exit(84);
        }
        requester_thread_valid = true;
    }

    if (scenario == kSignalCaseFullPipe)
    {
        discard raise(SIGTERM);
        atomicStoreExplicit(&signal_was_raised, true, memory_order_release);
    }
    else
    {
        if (threadCreate(&sender_thread, signalSenderMain, NULL) != kWThreadErrorNone)
        {
            _Exit(82);
        }
        sender_thread_valid = true;
    }

    runMainThread();
    _Exit(83); // runMainThread() must not return
}

// ---------------------------------------------------------------------------
// Parent-side driver
// ---------------------------------------------------------------------------

typedef struct
{
    unsigned int    record_count;
    signal_report_t first;
    int             exit_status;
    bool            exited_normally;
} signal_result_t;

static signal_result_t runSignalCase(signal_case_t scenario)
{
    int report_pipe[2];
    require(pipe(report_pipe) == 0, "failed to create the signal report pipe");

    pid_t child = fork();
    require(child >= 0, "failed to fork the signal scenario child");

    if (child == 0)
    {
        discard close(report_pipe[0]);
        runChild(scenario, report_pipe[1]);
    }

    discard close(report_pipe[1]);

    signal_result_t result = {0};
    signal_report_t record;

    for (;;)
    {
        ssize_t got = read(report_pipe[0], &record, sizeof(record));
        if (got <= 0)
        {
            break;
        }
        require(got == (ssize_t) sizeof(record), "received a truncated signal report record");
        require(record.magic == kReportMagic, "received a corrupted signal report record");
        if (result.record_count == 0)
        {
            result.first = record;
        }
        result.record_count++;
    }
    discard close(report_pipe[0]);

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for the signal scenario child");
    result.exited_normally = WIFEXITED(status);
    result.exit_status     = result.exited_normally ? WEXITSTATUS(status) : -1;
    return result;
}

static void checkCleanShutdown(const signal_result_t *result, int expected_status, const char *label)
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

    // Inside the async handler every graceful signal is blocked by sa_mask; the
    // callback observing them unblocked proves it ran from worker 0's event loop
    // and not from the handler's context.
    snprintf(message, sizeof(message), "%s: the shutdown callback ran inside the async signal handler context", label);
    require(result->first.stop_signals_blocked == 0, message);

    snprintf(message, sizeof(message), "%s: the exit observer ran outside the late worker-destruction phase", label);
    require(result->first.phase_is_destroying_workers == 1, message);

    snprintf(
        message, sizeof(message), "%s: exit status was %d instead of %d", label, result->exit_status, expected_status);
    require(result->exit_status == expected_status, message);
}

static void publishSignalDuringMailboxTake(void)
{
    signalmanagerTestSetPosixMailboxHook(NULL);
    require(raise(SIGTERM) == 0, "failed to publish the signal during mailbox take");
}

static bool signalMasksEqual(const sigset_t *lhs, const sigset_t *rhs)
{
    for (int signum = 1; signum < NSIG; ++signum)
    {
        if (sigismember(lhs, signum) != sigismember(rhs, signum))
        {
            return false;
        }
    }
    return true;
}

static int startup_boundary_report_fd = -1;

static void reportStartupBoundaryCleanup(void *userdata, int signum)
{
    discard             userdata;
    discard             signum;
    const unsigned char marker  = 1;
    const ssize_t       written = write(startup_boundary_report_fd, &marker, sizeof(marker));
    discard             written;
}

static void setupStartupBoundaryFixture(void)
{
    ww_construction_data_t init_data         = {0};
    init_data.workers_count                  = 1;
    init_data.ram_profile                    = kRamProfileS1Memory;
    init_data.mtu_size                       = 1500;
    init_data.internal_logger_data.log_level = child_log_level;
    init_data.core_logger_data.log_level     = child_log_level;
    init_data.network_logger_data.log_level  = child_log_level;
    init_data.dns_logger_data.log_level      = child_log_level;

    require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create the startup-boundary fixture");
    registerAtExitCallBack(reportStartupBoundaryCleanup, NULL);
}

static void runStartupFailureBoundaryCase(bool signal_before_boundary)
{
    int report_pipe[2];
    require(pipe(report_pipe) == 0, "failed to create the startup-boundary report pipe");

    pid_t child = fork();
    require(child >= 0, "failed to fork the startup-boundary child");
    if (child == 0)
    {
        discard close(report_pipe[0]);
        startup_boundary_report_fd = report_pipe[1];
        setupStartupBoundaryFixture();

        sigset_t extra;
        sigemptyset(&extra);
        sigaddset(&extra, SIGUSR1);
        require(pthread_sigmask(SIG_BLOCK, &extra, NULL) == 0, "failed to install the boundary mask fixture");

        sigset_t mask_before;
        require(pthread_sigmask(SIG_BLOCK, NULL, &mask_before) == 0, "failed to snapshot the boundary mask");

        if (signal_before_boundary)
        {
            require(raise(SIGTERM) == 0, "failed to publish the pre-boundary signal");
        }
        else
        {
            signalmanagerTestSetPosixMailboxHook(publishSignalDuringMailboxTake);
        }

        const application_shutdown_request_result_e result = signalmanagerArbitrateStartupFailure(47);
        require(result != kApplicationShutdownRequestUnavailable, "startup-failure arbitration was unavailable");

        sigset_t mask_after;
        require(pthread_sigmask(SIG_BLOCK, NULL, &mask_after) == 0, "failed to snapshot the restored boundary mask");
        require(signalMasksEqual(&mask_before, &mask_after), "startup-failure arbitration changed the signal mask");

        ww_lifecycle_context_t context;
        require(applicationShutdownGetSelectedContext(&context), "startup arbitration did not select cleanup scope");
        require(context.scope == kWwLifecycleStartupRollback, "startup arbitration selected runtime cleanup");

        if (signal_before_boundary)
        {
            require(applicationShutdownGetReason() == kApplicationShutdownReasonSignal,
                    "an already-pending signal lost startup-origin arbitration");
            require(applicationShutdownGetExitCode() == 128 + SIGTERM,
                    "an already-pending signal lost its exit status");
        }
        else
        {
            require(applicationShutdownGetReason() == kApplicationShutdownReasonStartupFailure,
                    "a signal deferred by the boundary replaced startup failure");
            require(applicationShutdownGetExitCode() == 47, "the deferred signal replaced startup failure status");
            signalmanagerConsumePendingShutdownSignal();
            require(applicationShutdownGetReason() == kApplicationShutdownReasonStartupFailure &&
                        applicationShutdownGetExitCode() == 47,
                    "later mailbox delivery replaced the accepted startup origin");
        }

        applicationShutdownCoordinate();
        _Exit(90);
    }

    discard       close(report_pipe[1]);
    unsigned int  cleanup_count = 0;
    unsigned char marker;
    while (read(report_pipe[0], &marker, sizeof(marker)) == (ssize_t) sizeof(marker))
    {
        cleanup_count += marker == 1;
    }
    discard close(report_pipe[0]);

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for the startup-boundary child");
    const int expected_status = signal_before_boundary ? 128 + SIGTERM : 47;
    require(WIFEXITED(status) && WEXITSTATUS(status) == expected_status,
            "startup-boundary child returned the wrong status");
    require(cleanup_count == 1, "startup-boundary cleanup was not coordinated exactly once");
}

static void testMailboxTakeDefersConcurrentSignal(void)
{
    pid_t child = fork();
    require(child >= 0, "failed to fork the mailbox race child");
    if (child == 0)
    {
        ww_construction_data_t init_data         = {0};
        init_data.workers_count                  = 1;
        init_data.ram_profile                    = kRamProfileS1Memory;
        init_data.mtu_size                       = 1500;
        init_data.internal_logger_data.log_level = child_log_level;
        init_data.core_logger_data.log_level     = child_log_level;
        init_data.network_logger_data.log_level  = child_log_level;
        init_data.dns_logger_data.log_level      = child_log_level;

        require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create the mailbox race fixture");
        signalmanagerTestSetPosixMailboxHook(publishSignalDuringMailboxTake);
        signalmanagerConsumePendingShutdownSignal();
        require(applicationShutdownGetPhase() == kApplicationShutdownRunning,
                "mailbox take consumed a signal that was still blocked");

        signalmanagerConsumePendingShutdownSignal();
        ww_lifecycle_context_t context;
        require(applicationShutdownGetPhase() == kApplicationShutdownRequested,
                "deferred signal was lost by mailbox clear");
        require(applicationShutdownGetReason() == kApplicationShutdownReasonSignal, "deferred signal lost its origin");
        require(applicationShutdownGetSelectedContext(&context), "deferred signal did not select cleanup scope");
        require(context.scope == kWwLifecycleStartupRollback, "pre-commit signal selected runtime shutdown");
        require(applicationShutdownGetExitCode() == 128 + SIGTERM, "deferred signal selected the wrong status");

        signalmanagerConsumePendingShutdownSignal();
        require(applicationShutdownGetExitCode() == 128 + SIGTERM,
                "empty mailbox consumption changed the accepted signal");
        _Exit(0);
    }

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for the mailbox race child");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "mailbox race child failed");
}

static void testAbortDoesNotBlockOnFullStdout(void)
{
    int pipe_fd[2];
    require(pipe(pipe_fd) == 0, "failed to create the fatal stdout pipe");

    const int write_flags = fcntl(pipe_fd[1], F_GETFL, 0);
    require(write_flags >= 0 && fcntl(pipe_fd[1], F_SETFL, write_flags | O_NONBLOCK) == 0,
            "failed to make the fatal stdout pipe nonblocking while filling it");
    unsigned char bytes[4096] = {0};
    while (write(pipe_fd[1], bytes, sizeof(bytes)) > 0)
    {
    }
    require(errno == EAGAIN || errno == EWOULDBLOCK, "failed to fill the fatal stdout pipe");
    require(fcntl(pipe_fd[1], F_SETFL, write_flags & ~O_NONBLOCK) == 0, "failed to restore blocking fatal stdout");

    pid_t child = fork();
    require(child >= 0, "failed to fork the fatal stdout child");
    if (child == 0)
    {
        require(dup2(pipe_fd[1], STDOUT_FILENO) == STDOUT_FILENO, "failed to redirect fatal stdout");
        discard close(pipe_fd[0]);
        discard close(pipe_fd[1]);
        abortProgramNow(73);
    }
    discard close(pipe_fd[1]);

    int   status = 0;
    pid_t waited = 0;
    for (unsigned int attempt = 0; attempt < 200U && waited == 0; ++attempt)
    {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == 0)
        {
            wwSleepMS(5);
        }
    }
    if (waited == 0)
    {
        discard kill(child, SIGKILL);
        discard waitpid(child, &status, 0);
    }
    discard close(pipe_fd[0]);

    require(waited == child, "abortProgramNow blocked on full stdout");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 73, "abortProgramNow returned the wrong status");
}

int main(void)
{
    signal_result_t result;

    runStartupFailureBoundaryCase(true);
    runStartupFailureBoundaryCase(false);
    testMailboxTakeDefersConcurrentSignal();
    testAbortDoesNotBlockOnFullStdout();

    // 1. SIGTERM while worker 0 is idle: full cleanup, 128 + SIGTERM.
    result = runSignalCase(kSignalCaseTermIdle);
    checkCleanShutdown(&result, 128 + SIGTERM, "SIGTERM idle");

    // 2. SIGTERM while another worker is busy inside a callback.
    result = runSignalCase(kSignalCaseTermBusyWorker);
    checkCleanShutdown(&result, 128 + SIGTERM, "SIGTERM busy worker");
    require(result.first.worker_was_busy == 1, "the busy worker never entered its callback");

    // 3. SIGINT status.
    result = runSignalCase(kSignalCaseIntStatus);
    checkCleanShutdown(&result, 128 + SIGINT, "SIGINT");

    // 4. A signal arriving after a programmatic success request but before
    //    worker 0 begins teardown. Worker 0 is held busy until both control
    //    bytes are in the self-pipe, so it drains the whole batch in one read:
    //    the request coalesces into the in-flight shutdown, and the signal's
    //    128 + signum wins over the initial zero deterministically.
    result = runSignalCase(kSignalCaseAfterSuccessRequest);
    checkCleanShutdown(&result, 128 + SIGTERM, "signal after success request");

    // 5. A full pipe is only a saturated wake edge; the signal-safe mailbox is
    //    still translated into the durable request.
    result = runSignalCase(kSignalCaseFullPipe);
    checkCleanShutdown(&result, 128 + SIGTERM, "SIGTERM with full wake pipe");

    // 6. A second stop signal forces an immediate exit through deliberately
    //    blocked cleanup, and no report is ever produced.
    result = runSignalCase(kSignalCaseSecondSignalForcesExit);
    require(result.exited_normally, "the forced-exit child did not exit normally");
    require(result.exit_status == 128 + SIGTERM, "the forced exit used the wrong status");
    require(result.record_count == 0, "blocked cleanup unexpectedly completed its report");

    return 0;
}
