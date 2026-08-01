/*
 * Process shutdown manager: orderly off-main shutdown requests.
 *
 * Every successful case exits the process, so each scenario runs in a forked
 * child that reports back over an inherited pipe. The child builds a real global
 * state with several workers, arranges for a chosen worker to call
 * requestProgramShutdown(), and lets runMainThread() drive the normal shutdown.
 *
 * What is being pinned:
 *   - registered shutdown callbacks run exactly once, on the main thread;
 *   - a non-zero worker can request shutdown, return, and still be joined;
 *   - exit-code arbitration is deterministic (first non-zero wins);
 *   - duplicate requests coalesce instead of forcing an immediate _Exit();
 *   - a requester really unwinds before worker 0 needs its locks;
 *   - a request that cannot be handed off reports failure to its caller.
 */

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
} shutdown_report_t;

typedef enum
{
    kScenarioWorkerSuccess = 0,
    kScenarioWorkerError,
    kScenarioTwoWorkers,
    kScenarioErrorThenSuccess,
    kScenarioSuccessThenError,
    kScenarioProbeMutex,
    kScenarioWorkerZero,
    kScenarioDuplicateRequests
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
static atomic_int  requesters_unwound;
static atomic_bool requesters_released;
static atomic_bool first_request_done;
static atomic_bool second_request_done;
static wmutex_t    probe_mutex;
static uint8_t     probe_mutex_acquired;
static uint8_t     unwind_target;

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

/* Wait until at least `target` requesters have returned from their request. */
static bool waitForUnwindCount(uint8_t target, unsigned int timeout_ms)
{
    for (unsigned int waited = 0; waited < timeout_ms; waited += 5)
    {
        if (atomicLoadExplicit(&requesters_unwound, memory_order_acquire) >= (w_atomic_int_value_t) target)
        {
            return true;
        }
        wwSleepMS(5);
    }
    return atomicLoadExplicit(&requesters_unwound, memory_order_acquire) >= (w_atomic_int_value_t) target;
}

/*
 * Registered shutdown callback. It runs before the global-state callback (LIFO),
 * so the other workers are still alive here - which is exactly what makes the
 * probe-mutex case meaningful.
 */
static void reportingExitCallback(void *userdata, int signum)
{
    discard userdata;
    discard signum;

    if (child_scenario == kScenarioProbeMutex)
    {
        // If the requester had blocked inside requestProgramShutdown() while
        // holding this mutex, this would deadlock instead of acquiring it.
        mutexLock(&probe_mutex);
        probe_mutex_acquired = 1;
        mutexUnlock(&probe_mutex);
    }

    if (child_scenario == kScenarioErrorThenSuccess || child_scenario == kScenarioSuccessThenError)
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
     * The wait is the real assertion: worker 0 is inside cleanup here and the
     * requesting workers have not been joined yet, so a requester that blocked
     * waiting for shutdown could never satisfy it. It resolves quickly when the
     * requesters were free to unwind, and times out into a reported failure when
     * they were not.
     */
    const bool all_unwound = waitForUnwindCount(unwind_target, kWaitTimeoutMs);

    shutdown_report_t report        = {0};
    report.magic                    = kReportMagic;
    report.callback_tid             = (uint64_t) getTID();
    report.main_tid                 = GSTATE.main_thread_id;
    report.requesters_unwound       = (uint8_t) all_unwound;
    report.probe_mutex_acquired     = probe_mutex_acquired;
    report.handoff_reported_failure = 0;

    ssize_t written = write(child_report_fd, &report, sizeof(report));
    discard written;
}

static void noteUnwound(void)
{
    discard atomicIncExplicit(&requesters_unwound, memory_order_acq_rel);
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

    case kScenarioTwoWorkers:
    default:
        require(requestProgramShutdown(0), "the concurrent request was rejected");
        break;
    }

    noteUnwound();
    atomicStoreExplicit(&second_request_done, true, memory_order_release);
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

    init_data.internal_logger_data.log_level = child_log_level;
    init_data.core_logger_data.log_level     = child_log_level;
    init_data.network_logger_data.log_level  = child_log_level;
    init_data.dns_logger_data.log_level      = child_log_level;

    createGlobalState(init_data);

    // Registered after the global-state callback, so LIFO order runs this one
    // first: while the other workers are still alive and joinable.
    registerAtExitCallBack(reportingExitCallback, NULL);

    switch (scenario)
    {
    case kScenarioTwoWorkers:
    case kScenarioErrorThenSuccess:
    case kScenarioSuccessThenError:
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

    default:
        unwind_target = 1;
        posts_count   = 1;
        posts[0].wid  = 1;
        posts[0].cb   = firstRequestEventCB;
        break;
    }

    wthread_t poster;
    if (threadCreate(&poster, requestPosterMain, NULL) != kWThreadErrorNone)
    {
        _Exit(71);
    }

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

        // The manager exists but signalmanagerStart() never ran, so there is no
        // control transport to worker 0.
        GSTATE.signal_manager = signalmanagerCreate();

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

    // An error recorded by the rejected request still wins over a later zero,
    // exactly as it does on the orderly path.
    require(runHandoffFailureChild(true, 0) == 1, "the hard fallback discarded an already recorded error status");
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

    // 6. The requester holds a lock across the request and releases it after
    //    returning; a shutdown callback on worker 0 must be able to take it.
    result = runScenario(kScenarioProbeMutex);
    checkCommonInvariants(&result, "probe mutex");
    require(result.first.probe_mutex_acquired == 1, "the shutdown callback could not acquire the requester's mutex");
    expectExitStatus(&result, 0, "probe mutex");

    // 7. A worker-0 request follows the same once-only state machine and does
    //    not recursively execute callbacks.
    result = runScenario(kScenarioWorkerZero);
    checkCommonInvariants(&result, "worker zero");
    expectExitStatus(&result, 0, "worker zero");

    // 8. Duplicate programmatic requests coalesce instead of forcing an exit.
    result = runScenario(kScenarioDuplicateRequests);
    checkCommonInvariants(&result, "duplicate requests");
    expectExitStatus(&result, 0, "duplicate requests");

    // 9. Handoff failure before worker 0 is available.
    testHandoffFailure();

    return 0;
}
