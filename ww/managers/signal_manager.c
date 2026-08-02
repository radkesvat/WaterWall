/*
 * Signal handling runtime and process shutdown dispatch.
 *
 * There are exactly three shutdown entry points, with deliberately different
 * contracts:
 *
 *   requestProgramShutdown(code)  thread-safe orderly request. Records the exit
 *                                 status, schedules the shutdown sequence on
 *                                 worker 0 and returns to its caller, which
 *                                 must then unwind normally. It never waits for
 *                                 teardown, so worker 0 can join the requester.
 *   abortProgramNow(code)         immediate _Exit() without registered cleanup,
 *                                 for corrupted state or failures reached while
 *                                 arbitrary locks may be held.
 *   terminateProgram(code)        legacy compatibility entry: orderly shutdown
 *                                 on the main thread, hard abort elsewhere.
 *
 * The real shutdown work (running registered exit handlers, joining worker
 * threads and tearing down the global state) always runs on Waterwall's main
 * worker thread (worker 0), exactly once. Signal handlers and the Windows
 * console handler only *request* shutdown; they never touch locks owned by the
 * rest of the program:
 *   - POSIX: the async signal handler writes the signal number to a self-pipe
 *     whose read end is watched at high priority by worker 0's event loop.
 *     requestProgramShutdown() writes a programmatic-request marker to the same
 *     pipe. The pipe is dedicated control traffic, so it is never blocked by
 *     the normal application event-admission gate.
 *   - Windows: the console control handler and requestProgramShutdown() post a
 *     control event to worker 0's loop (bypassing that same gate), and a
 *     close/logoff/shutdown handler waits on a bounded event while the main
 *     thread performs cleanup.
 * This removes the shutdown deadlocks that happened when cleanup ran directly
 * inside an async signal/console handler, without converting an off-main
 * orderly shutdown into an immediate _Exit() that skips cleanup.
 */

#include "signal_manager.h"
#include "global_state.h"

#include <errno.h>

static signal_manager_t *signalmanager_gstate = NULL;

#define SHUTDOWN_PIPE_READ  0
#define SHUTDOWN_PIPE_WRITE 1

enum
{
    // Self-pipe marker for a programmatic (non-signal) shutdown request. Real
    // signal numbers are always >= 1, so 0 is unambiguous.
    kShutdownRequestMarker = 0
};

#if defined(OS_WIN)
enum
{
    // Bounded time a console close/logoff/shutdown handler waits for the main
    // thread to finish teardown before returning (and letting the OS kill us).
    kShutdownWaitTimeoutMs = 10000
};

static atomic_int windows_ctrl_handlers_active;
// First console stop event flag; a second one forces an immediate exit.
static atomic_bool windows_stop_event_seen;
#else
/*
 * Minimal state the POSIX async handler is allowed to touch. It must not
 * dereference signalmanager_gstate, which can be freed during late teardown.
 * Both are reset while the handled signals are blocked in signalmanagerDestroy.
 */
static volatile sig_atomic_t posix_shutdown_pipe_write_fd = -1;
static volatile sig_atomic_t posix_stop_signal_seen       = 0;
#endif

static const char *signalName(int signum)
{
    switch (signum)
    {
#ifdef SIGABRT
    case SIGABRT:
        return "SIGABRT";
#endif
#ifdef SIGALRM
    case SIGALRM:
        return "SIGALRM";
#endif
#ifdef SIGBUS
    case SIGBUS:
        return "SIGBUS";
#endif
#ifdef SIGFPE
    case SIGFPE:
        return "SIGFPE";
#endif
#ifdef SIGHUP
    case SIGHUP:
        return "SIGHUP";
#endif
#ifdef SIGILL
    case SIGILL:
        return "SIGILL";
#endif
#ifdef SIGINT
    case SIGINT:
        return "SIGINT";
#endif
#ifdef SIGPIPE
    case SIGPIPE:
        return "SIGPIPE";
#endif
#ifdef SIGQUIT
    case SIGQUIT:
        return "SIGQUIT";
#endif
#ifdef SIGSEGV
    case SIGSEGV:
        return "SIGSEGV";
#endif
#ifdef SIGTERM
    case SIGTERM:
        return "SIGTERM";
#endif
#ifdef SIGTRAP
    case SIGTRAP:
        return "SIGTRAP";
#endif
#ifdef SIGUSR1
    case SIGUSR1:
        return "SIGUSR1";
#endif
#ifdef SIGUSR2
    case SIGUSR2:
        return "SIGUSR2";
#endif
    default:
        return "UNKNOWN_SIGNAL";
    }
}

/**
 * @brief Write a short diagnostic without touching the logger machinery.
 *
 * Used on shutdown paths where loggers may already be destroyed.
 */
static void writeShutdownDiag(const char *msg)
{
    int     written = (int) write(STDOUT_FILENO, msg, stringLength(msg));
    discard written;
}

// --------------------------------------------------------------------------
// Shutdown phase and exit-code arbitration
// --------------------------------------------------------------------------

program_shutdown_phase_e signalmanagerGetShutdownPhase(void)
{
    if (signalmanager_gstate == NULL)
    {
        return kProgramShutdownRunning;
    }

    return (program_shutdown_phase_e) atomicLoadExplicit(&signalmanager_gstate->shutdown_phase, memory_order_acquire);
}

/**
 * @brief Move the phase forward to @p target, never backwards.
 *
 * @return true when this call performed the transition.
 */
static bool advanceShutdownPhase(program_shutdown_phase_e target)
{
    w_atomic_int_value_t current = atomicLoadExplicit(&signalmanager_gstate->shutdown_phase, memory_order_acquire);

    while (current < (w_atomic_int_value_t) target)
    {
        if (atomicCompareExchangeExplicit(&signalmanager_gstate->shutdown_phase,
                                          &current,
                                          (w_atomic_int_value_t) target,
                                          memory_order_acq_rel,
                                          memory_order_acquire))
        {
            return true;
        }
    }
    return false;
}

/*
 * Exit-code policy (deterministic, independent of thread scheduling):
 *   - the initial exit code is zero;
 *   - the first non-zero code wins;
 *   - a later zero can never overwrite a recorded error;
 *   - a later non-zero can never replace an earlier non-zero.
 * A stop signal received before shutdown starts therefore records 128 + signum
 * only when no error was recorded yet. The alternative policy (signal status
 * always wins) is deliberately not used; see SHUTDOWN_IMPLEMENTATION_PLAN 4.3.
 */
void signalmanagerSetExitCode(int exit_code)
{
    if (signalmanager_gstate == NULL || exit_code == 0)
    {
        return;
    }

    w_atomic_int_value_t expected = 0;
    while (! atomicCompareExchangeExplicit(&signalmanager_gstate->exit_code,
                                           &expected,
                                           (w_atomic_int_value_t) exit_code,
                                           memory_order_acq_rel,
                                           memory_order_acquire))
    {
        if (expected != 0)
        {
            // An error code is already recorded and wins.
            return;
        }
    }
}

int signalmanagerGetExitCode(void)
{
    if (signalmanager_gstate == NULL)
    {
        return 0;
    }

    return (int) atomicLoadExplicit(&signalmanager_gstate->exit_code, memory_order_acquire);
}

// --------------------------------------------------------------------------
// Exit callback registry
// --------------------------------------------------------------------------

/**
 * @brief Register one shutdown callback in reverse-priority slots.
 *
 * Slots are filled from the top down and traversed bottom-up, which yields LIFO
 * execution order.
 *
 * @param handle Callback function.
 * @param userdata Callback context.
 */
void registerAtExitCallBack(SignalHandler handle, void *userdata)
{
    assert(signalmanager_gstate != NULL);
    signal_manager_t *sm = signalmanager_gstate;

    mutexLock(&(sm->mutex));

    if (sm->callbacks_frozen)
    {
        mutexUnlock(&(sm->mutex));
        printError("SignalManager: shutdown callback registration rejected, shutdown already started");
        return;
    }

    // The capacity check belongs inside the mutex: handlers_len is only stable
    // while the registry lock is held.
    if (sm->handlers_len >= kMaxSigHandles)
    {
        mutexUnlock(&(sm->mutex));
        printError("SignalManager: Too many atexit handlers, max is %d", kMaxSigHandles);
        _Exit(1);
    }

    for (int i = kMaxSigHandles - 1; i >= 0; i--)
    {
        if (sm->handlers[i].handle == NULL)
        {
            sm->handlers[i] = (signal_handler_t) {.handle = handle, .userdata = userdata};
            sm->handlers_len++;
            mutexUnlock(&(sm->mutex));

            return;
        }
    }
    mutexUnlock(&(sm->mutex));

    printError("SignalManager: Too many atexit handlers, max is %d", kMaxSigHandles);
    _Exit(1);
}

/**
 * @brief Remove a previously registered shutdown callback.
 *
 * @param handle Callback function.
 * @param userdata Callback context.
 */
void removeAtExitCallBack(SignalHandler handle, void *userdata)
{
    assert(signalmanager_gstate != NULL);
    signal_manager_t *sm = signalmanager_gstate;

    mutexLock(&(sm->mutex));

    if (sm->callbacks_frozen)
    {
        // The list is being traversed by worker 0; removals are ignored.
        mutexUnlock(&(sm->mutex));
        return;
    }

    for (int i = 0; i < kMaxSigHandles; i++)
    {
        if (sm->handlers[i].handle == handle && sm->handlers[i].userdata == userdata)
        {
            sm->handlers[i] = (signal_handler_t) {.handle = NULL, .userdata = NULL};
            sm->handlers_len--;
            mutexUnlock(&(sm->mutex));

            return;
        }
    }
    // not found...
    mutexUnlock(&(sm->mutex));
}

/*
 * Frozen snapshot of the callback list. Only worker 0 traverses it and only
 * once, so a file-static buffer avoids putting 8 KiB on the shutdown stack.
 */
static signal_handler_t frozen_handlers[kMaxSigHandles];

/**
 * @brief Freeze the registry and run every callback exactly once, in LIFO order.
 *
 * The registry mutex is never held while a callback runs. A callback that wants
 * to influence the result records it through signalmanagerSetExitCode(); it must
 * not try to "continue" the sequence by re-entering the shutdown API.
 */
static void runExitCallbacksOnce(void)
{
    signal_manager_t *sm = signalmanager_gstate;

    mutexLock(&(sm->mutex));
    if (sm->callbacks_frozen)
    {
        mutexUnlock(&(sm->mutex));
        return;
    }
    sm->callbacks_frozen = true;
    memoryCopy(frozen_handlers, sm->handlers, sizeof(frozen_handlers));
    mutexUnlock(&(sm->mutex));

    for (unsigned int i = 0; i < kMaxSigHandles; i++)
    {
        if (frozen_handlers[i].handle != NULL)
        {
            frozen_handlers[i].handle(frozen_handlers[i].userdata, 0);
        }
    }
}

// --------------------------------------------------------------------------
// Main-thread shutdown handoff
// --------------------------------------------------------------------------

static bool onMainThread(void)
{
    return (uint64_t) getTID() == GSTATE.main_thread_id;
}

void signalmanagerEnterFinalizing(void)
{
    if (signalmanager_gstate == NULL)
    {
        return;
    }
    discard advanceShutdownPhase(kProgramShutdownFinalizing);
}

/**
 * @brief The once-only shutdown executor. Worker 0 / main thread only.
 *
 * Returns without doing anything when another worker-0 pass already claimed the
 * sequence (for example a shutdown callback that re-entered the API). Otherwise
 * it runs the registered callbacks and does not return: the global-state
 * callback destroys the process state and calls exit().
 */
void signalmanagerRunShutdownOnMainThread(void)
{
    signal_manager_t *sm = signalmanager_gstate;
    if (sm == NULL)
    {
        exit(0);
    }

    assert(onMainThread());

    // 1. Claim the REQUESTED -> STOPPING transition. Only worker 0 performs it,
    //    and only the thread that wins the transition runs cleanup.
    if (! advanceShutdownPhase(kProgramShutdownStopping))
    {
        return;
    }

    // 2. Publish the compatibility flag now that shutdown is really starting.
    atomicStoreExplicit(&GSTATE.application_stopping_flag, true, memory_order_release);

    writeShutdownDiag("SignalManager: Exiting... \n");

    // 3.-5. Freeze the registry and run every callback exactly once. The
    //       global-state callback stops nodes, stops and joins the workers and
    //       finishes by destroying global state and exiting the process.
    runExitCallbacksOnce();

    // Reached only when no callback terminated the process.
    signalmanagerEnterFinalizing();
    writeShutdownDiag("SignalManager: Finished\n");
    exit(signalmanagerGetExitCode());
}

#if defined(OS_WIN)
static void worker0ShutdownEventCB(wevent_t *ev)
{
    discard ev;
    signalmanagerRunShutdownOnMainThread();
}
#else
static void worker0ShutdownPipeReadCB(wio_t *io, sbuf_t *buf)
{
    discard io;
    // Runs on worker 0 / main thread. Process the whole received batch before
    // choosing the final exit code, then reclaim the buffer and run the real
    // shutdown (which tears down global state and exits the process).
    const uint8_t *bytes = (const uint8_t *) sbufGetRawPtr(buf);
    const uint32_t len   = sbufGetLength(buf);

    for (uint32_t i = 0; i < len; i++)
    {
        if (bytes[i] != kShutdownRequestMarker)
        {
            // OS signal: arbitrate 128 + signum. Doing it here rather than in
            // the async handler keeps normal C synchronization available.
            signalmanagerSetExitCode(128 + (int) bytes[i]);
        }
    }

    reuseBuffer(buf);
    signalmanagerRunShutdownOnMainThread();
}
#endif

/**
 * @brief Deliver a shutdown-control wakeup to worker 0.
 *
 * Never blocks and never runs cleanup. Returns false when no handoff is
 * possible, which the caller must treat as a hard-abort condition.
 */
static bool wakeWorker0Shutdown(void)
{
#if defined(OS_WIN)
    if (WORKERS == NULL)
    {
        return false;
    }

    wevent_t ev;
    memoryZero(&ev, sizeof(ev));
    ev.cb = worker0ShutdownEventCB;
    weventSetPriority(&ev, WEVENT_HIGH_PRIORITY);

    /*
     * Route through the worker rather than reading GSTATE.shortcut_loops: the
     * shortcut table is never updated when worker 0 destroys its loop, so it can
     * dangle if worker 0's loop exits unexpectedly while another thread is
     * requesting shutdown. workerPostControlEvent() resolves and posts under
     * worker 0's control mutex, and the control event is still admitted after
     * normal application event posting has been closed. The event is copied into
     * the loop's queue, so the stack object above need not outlive this call.
     */
    return workerPostControlEvent(getWorker(0), &ev);
#else
    signal_manager_t *sm = signalmanager_gstate;
    if (sm == NULL)
    {
        return false;
    }
    const int fd = sm->shutdown_pipe[SHUTDOWN_PIPE_WRITE];
    if (fd < 0)
    {
        return false;
    }

    unsigned char byte = (unsigned char) kShutdownRequestMarker;
    ssize_t       w;
    do
    {
        w = write(fd, &byte, 1);
    } while (w < 0 && errno == EINTR);

    return w == 1;
#endif
}

bool requestProgramShutdown(int exit_code)
{
    signal_manager_t *sm = signalmanager_gstate;
    if (sm == NULL)
    {
        // No shutdown manager yet: there is nothing that could execute an
        // orderly sequence, so the caller must use its documented fallback.
        return false;
    }

    signalmanagerSetExitCode(exit_code);

    /*
     * The claim and the handoff are a single decision and must be serialized.
     * Observing kProgramShutdownRequested is not on its own evidence that a
     * shutdown was accepted: the thread that made that claim may still be inside
     * its wakeup, and that wakeup may yet fail. A concurrent caller therefore
     * waits here for an in-progress handoff to publish its outcome, instead of
     * inferring "accepted" from the phase alone.
     *
     * This cannot deadlock: nothing reachable under this lock waits on a
     * shutdown requester. The wakeup is a non-blocking pipe write (POSIX) or a
     * bounded control-event post (Windows).
     */
    mutexLock(&(sm->request_mutex));

    if (signalmanagerGetShutdownPhase() != kProgramShutdownRunning)
    {
        // A shutdown was already accepted and is in flight: REQUESTED with a
        // successful handoff behind it, or STOPPING/FINALIZING. This request
        // coalesces into it and needs no second wakeup.
        mutexUnlock(&(sm->request_mutex));
        return true;
    }

    // Claim RUNNING -> REQUESTED.
    w_atomic_int_value_t expected = (w_atomic_int_value_t) kProgramShutdownRunning;
    if (! atomicCompareExchangeExplicit(&sm->shutdown_phase,
                                        &expected,
                                        (w_atomic_int_value_t) kProgramShutdownRequested,
                                        memory_order_acq_rel,
                                        memory_order_acquire))
    {
        // Only worker 0 advances the phase without holding request_mutex, and it
        // does so only to begin the real shutdown, so losing this race still
        // means a shutdown is under way.
        mutexUnlock(&(sm->request_mutex));
        return true;
    }

    if (! wakeWorker0Shutdown())
    {
        /*
         * Nothing accepted the request. Roll back only our own REQUESTED claim
         * with a compare/exchange: an unconditional store could regress a phase
         * that worker 0 advanced to STOPPING meanwhile - for example when an OS
         * signal reached the control pipe while this handoff was failing.
         */
        w_atomic_int_value_t requested   = (w_atomic_int_value_t) kProgramShutdownRequested;
        const bool           rolled_back = atomicCompareExchangeExplicit(&sm->shutdown_phase,
                                                               &requested,
                                                               (w_atomic_int_value_t) kProgramShutdownRunning,
                                                               memory_order_acq_rel,
                                                               memory_order_acquire);
        mutexUnlock(&(sm->request_mutex));

        // A failed rollback means someone else already began the real shutdown,
        // so this request ended up with an executor after all.
        return ! rolled_back;
    }

    mutexUnlock(&(sm->request_mutex));
    return true;
}

_Noreturn void abortProgramNow(int exit_code)
{
    signalmanagerSetExitCode(exit_code);

    const int code = (signalmanager_gstate != NULL) ? signalmanagerGetExitCode() : exit_code;

    writeShutdownDiag("SignalManager: aborting immediately, registered cleanup is SKIPPED\n");
    _Exit(code);
}

/**
 * @brief Crash-signal handler: no Waterwall cleanup.
 *
 * Restores the default disposition and re-raises so the process still produces a
 * proper crash / core dump.
 */
static void fatalSignalHandler(int signum)
{
    signal(signum, SIG_DFL);
    raise(signum);
    _Exit(128 + signum);
}

#if defined(OS_WIN)

/**
 * @brief Windows console control dispatcher.
 *
 * Non-destructive: it does not log, run exit handlers, join workers or tear
 * down global state. It only hands shutdown to worker 0 and (for close/logoff/
 * shutdown events) waits a bounded time for the main thread to finish cleanup.
 *
 * @param CtrlType Windows control event code.
 * @return TRUE when handled.
 */
static BOOL WINAPI CtrlHandler(_In_ DWORD CtrlType)
{
    atomicIncExplicit(&windows_ctrl_handlers_active, memory_order_acq_rel);

    int  exit_code;
    bool wait_for_cleanup = false;
    BOOL handled          = TRUE;

    switch (CtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        exit_code = 130;
        break;

    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        // Keep the exit code already chosen by the application, default 0.
        exit_code        = signalmanagerGetExitCode();
        wait_for_cleanup = true;
        break;

    default:
        handled = FALSE;
        goto done;
    }

    signal_manager_t *sm = signalmanager_gstate;
    if (sm == NULL)
    {
        ExitProcess((UINT) exit_code);
    }

    // A second console stop event is the operator escape hatch: force an
    // immediate exit rather than waiting for a stuck teardown. Arbitrate this
    // event's own status first, otherwise a Ctrl+C following a close/logoff
    // event that started shutdown with status 0 would still exit 0 instead of
    // recording 130.
    if (atomicExchangeExplicit(&windows_stop_event_seen, true, memory_order_acq_rel))
    {
        signalmanagerSetExitCode(exit_code);
        ExitProcess((UINT) signalmanagerGetExitCode());
    }

    // Same state machine and exit-code arbitration as POSIX: record the status,
    // hand the sequence to worker 0, never run cleanup here.
    if (! requestProgramShutdown(exit_code))
    {
        // Nothing to hand off to; exit now rather than run teardown here.
        ExitProcess((UINT) signalmanagerGetExitCode());
    }

    if (wait_for_cleanup)
    {
        // The OS terminates the process once we return from a close/logoff/
        // shutdown event, so block (bounded) until the main thread signals that
        // teardown finished.
        HANDLE ev = (HANDLE) sm->shutdown_complete_event;
        if (ev != NULL)
        {
            WaitForSingleObject(ev, kShutdownWaitTimeoutMs);
        }
    }
done:
    atomicDecExplicit(&windows_ctrl_handlers_active, memory_order_acq_rel);
    return handled;
}

static void installWindowsFatalHandlers(void)
{
    if (signalmanager_gstate->handle_sigill)
    {
        signal(SIGILL, fatalSignalHandler);
    }
    if (signalmanager_gstate->handle_sigfpe)
    {
        signal(SIGFPE, fatalSignalHandler);
    }
    if (signalmanager_gstate->handle_sigabrt)
    {
        signal(SIGABRT, fatalSignalHandler);
    }
    if (signalmanager_gstate->handle_sigsegv)
    {
        signal(SIGSEGV, fatalSignalHandler);
    }
}

#else // POSIX

/**
 * @brief Build the set of graceful signals routed through main-thread shutdown.
 */
static void buildGracefulSignalSet(sigset_t *set)
{
    sigemptyset(set);
    signal_manager_t *sm = signalmanager_gstate;
    if (sm == NULL)
    {
        return;
    }
    if (sm->handle_sigint)
    {
        sigaddset(set, SIGINT);
    }
    if (sm->handle_sigterm)
    {
        sigaddset(set, SIGTERM);
    }
    if (sm->handle_sigquit)
    {
        sigaddset(set, SIGQUIT);
    }
    if (sm->handle_sighup)
    {
        sigaddset(set, SIGHUP);
    }
    if (sm->handle_sigalrm)
    {
        sigaddset(set, SIGALRM);
    }
}

static int createShutdownPipe(int fds[2])
{
    if (pipe(fds) != 0)
    {
        return -1;
    }
    for (int i = 0; i < 2; ++i)
    {
        int fl = fcntl(fds[i], F_GETFL, 0);
        if (fl != -1)
        {
            fcntl(fds[i], F_SETFL, fl | O_NONBLOCK);
        }
        int fd_fl = fcntl(fds[i], F_GETFD, 0);
        if (fd_fl != -1)
        {
            fcntl(fds[i], F_SETFD, fd_fl | FD_CLOEXEC);
        }
    }
    return 0;
}

/**
 * @brief Async-signal handler for graceful signals.
 *
 * Strictly minimal and async-signal-safe: it preserves errno, consults only
 * `volatile sig_atomic_t` statics (never the manager object, which can be freed
 * during late teardown) and performs a single write() to the self-pipe. Exit
 * code arbitration and the shutdown state transitions happen later, in worker
 * 0's pipe callback, where normal C synchronization and logging are safe.
 *
 * A second handled stop signal forces an immediate exit so a stuck teardown
 * cannot trap the operator.
 */
static void posixGracefulSignalHandler(int signum)
{
    int saved_errno = errno;

    if (posix_stop_signal_seen != 0)
    {
        _Exit(128 + signum);
    }
    posix_stop_signal_seen = 1;

    const int fd = (int) posix_shutdown_pipe_write_fd;
    if (fd < 0)
    {
        // No handoff available (very early, or the manager was already torn
        // down): restore the default disposition and re-raise.
        signal(signum, SIG_DFL);
        raise(signum);
        errno = saved_errno;
        return;
    }

    unsigned char byte = (unsigned char) signum;
    ssize_t       w;
    do
    {
        w = write(fd, &byte, 1);
    } while (w < 0 && errno == EINTR);

    if (w != 1)
    {
        // Documented hard-exit fallback: the request cannot reach worker 0.
        _Exit(128 + signum);
    }

    errno = saved_errno;
}

static void restoreOneSignalDefault(int signum)
{
    struct sigaction sa;
    memoryZero(&sa, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    discard sigaction(signum, &sa, NULL);
}

static void restorePosixSignalHandlers(void)
{
    signal_manager_t *sm = signalmanager_gstate;
    if (sm == NULL)
    {
        return;
    }

    sigset_t graceful;
    buildGracefulSignalSet(&graceful);
    pthread_sigmask(SIG_BLOCK, &graceful, NULL);

    if (sm->handle_sigint)
    {
        restoreOneSignalDefault(SIGINT);
    }
    if (sm->handle_sigterm)
    {
        restoreOneSignalDefault(SIGTERM);
    }
    if (sm->handle_sigquit)
    {
        restoreOneSignalDefault(SIGQUIT);
    }
    if (sm->handle_sighup)
    {
        restoreOneSignalDefault(SIGHUP);
    }
    if (sm->handle_sigalrm)
    {
        restoreOneSignalDefault(SIGALRM);
    }
    if (sm->handle_sigill)
    {
        restoreOneSignalDefault(SIGILL);
    }
    if (sm->handle_sigfpe)
    {
        restoreOneSignalDefault(SIGFPE);
    }
    if (sm->handle_sigabrt)
    {
        restoreOneSignalDefault(SIGABRT);
    }
    if (sm->handle_sigsegv)
    {
        restoreOneSignalDefault(SIGSEGV);
    }
}

static void installOneSigaction(int signum, void (*handler)(int), const sigset_t *mask)
{
    struct sigaction sa;
    memoryZero(&sa, sizeof(sa));
    sa.sa_handler = handler;
    if (mask != NULL)
    {
        sa.sa_mask = *mask;
    }
    else
    {
        sigemptyset(&sa.sa_mask);
    }
    sa.sa_flags = 0;
    if (sigaction(signum, &sa, NULL) != 0)
    {
        printError("Error setting %s signal handler", signalName(signum));
        _Exit(1);
    }
}

static void installPosixSignalHandlers(void)
{
    signal_manager_t *sm = signalmanager_gstate;

    // While a graceful handler runs, block all graceful signals so its tiny body
    // is not re-entered.
    sigset_t graceful_mask;
    buildGracefulSignalSet(&graceful_mask);

    if (sm->handle_sigint)
    {
        installOneSigaction(SIGINT, posixGracefulSignalHandler, &graceful_mask);
    }
    if (sm->handle_sigterm)
    {
        installOneSigaction(SIGTERM, posixGracefulSignalHandler, &graceful_mask);
    }
    if (sm->handle_sigquit)
    {
        installOneSigaction(SIGQUIT, posixGracefulSignalHandler, &graceful_mask);
    }
    if (sm->handle_sighup)
    {
        installOneSigaction(SIGHUP, posixGracefulSignalHandler, &graceful_mask);
    }
    if (sm->handle_sigalrm)
    {
        installOneSigaction(SIGALRM, posixGracefulSignalHandler, &graceful_mask);
    }

    // Crash signals reset to default and re-raise; they never run cleanup.
    if (sm->handle_sigill)
    {
        installOneSigaction(SIGILL, fatalSignalHandler, NULL);
    }
    if (sm->handle_sigfpe)
    {
        installOneSigaction(SIGFPE, fatalSignalHandler, NULL);
    }
    if (sm->handle_sigabrt)
    {
        installOneSigaction(SIGABRT, fatalSignalHandler, NULL);
    }
    if (sm->handle_sigsegv)
    {
        installOneSigaction(SIGSEGV, fatalSignalHandler, NULL);
    }

    // Keep SIGPIPE ignored instead of routing it through shutdown.
    if (sm->handle_sigpipe)
    {
        signal(SIGPIPE, SIG_IGN);
    }
}

#endif // OS_WIN

void signalmanagerBlockHandledSignalsForCurrentThread(void)
{
#if defined(OS_WIN)
    // Windows uses the console control handler; there is nothing to block here.
#else
    assert(signalmanager_gstate != NULL);
    sigset_t set;
    buildGracefulSignalSet(&set);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
#endif
}

/**
 * @brief Install configured OS signal handlers and wire the worker-0 handoff.
 */
void signalmanagerStart(void)
{
    assert(signalmanager_gstate != NULL);

    if (signalmanager_gstate->started)
    {
        printError("Error double signalmanagerStart()");
        _Exit(1);
    }

    signalmanager_gstate->started = true;

#if defined(OS_WIN)
    signalmanager_gstate->shutdown_complete_event = (void *) CreateEvent(NULL, TRUE, FALSE, NULL);
    if (signalmanager_gstate->shutdown_complete_event == NULL)
    {
        printError("Failed to create shutdown completion event!");
        _Exit(1);
    }

    if (! SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        printError("Failed to set console control handler!");
        _Exit(1);
    }

    installWindowsFatalHandlers();
#else
    wloop_t *loop = getWorkerLoop(0);
    assert(loop != NULL);

    if (createShutdownPipe(signalmanager_gstate->shutdown_pipe) != 0)
    {
        printError("Failed to create shutdown self-pipe!");
        _Exit(1);
    }

    // Worker 0 watches the read end at high priority and runs the real shutdown.
    wio_t *io = wRead(loop, signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_READ], worker0ShutdownPipeReadCB);
    if (io == NULL)
    {
        printError("Failed to register shutdown self-pipe with worker 0 event loop\n");
        _Exit(EXIT_FAILURE);
    }
    assert(io != NULL);
    weventSetPriority(io, WEVENT_HIGH_PRIORITY);

    // Publish the write end into signal-safe storage before any handler that
    // uses it can run.
    posix_shutdown_pipe_write_fd = (sig_atomic_t) signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE];

    installPosixSignalHandlers();

    // Handlers and the self-pipe are ready, so deliver graceful signals to the
    // main thread now (worker threads inherited the blocked mask that was set in
    // createGlobalState() before they were spawned).
    sigset_t graceful;
    buildGracefulSignalSet(&graceful);
    pthread_sigmask(SIG_UNBLOCK, &graceful, NULL);
#endif
}

signal_manager_t *signalmanagerCreate(void)
{
    assert(signalmanager_gstate == NULL);
    signalmanager_gstate = memoryAllocate(sizeof(signal_manager_t));

    *signalmanager_gstate = (signal_manager_t) {.handlers_len     = 0,
                                                .exit_code        = 0,
                                                .shutdown_phase   = (w_atomic_int_value_t) kProgramShutdownRunning,
                                                .callbacks_frozen = false,
                                                .started          = false,
                                                .raise_defaults   = true,
                                                .handle_sigint    = true,
                                                .handle_sigquit   = true,
                                                .handle_sighup    = false, // exits after ssh closed even with nohup
                                                .handle_sigill    = false,
                                                .handle_sigfpe    = true,
                                                .handle_sigabrt   = false,
                                                .handle_sigsegv   = false,
                                                .handle_sigterm   = true,
                                                .handle_sigpipe   = true,
                                                .handle_sigalrm   = true};

#if defined(OS_WIN)
    signalmanager_gstate->shutdown_complete_event = NULL;
#else
    signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_READ]  = -1;
    signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE] = -1;
#endif

    mutexInit(&(signalmanager_gstate->mutex));
    mutexInit(&(signalmanager_gstate->request_mutex));
    return signalmanager_gstate;
}

signal_manager_t *signalmanagerGet(void)
{
    assert(signalmanager_gstate != NULL);
    return signalmanager_gstate;
}

void signalmanagerSet(signal_manager_t *sm)
{
    assert(signalmanager_gstate == NULL);
    signalmanager_gstate = sm;
}

void signalmanagerDestroy(void)
{
    assert(signalmanager_gstate != NULL);

#if defined(OS_WIN)
    SetConsoleCtrlHandler(CtrlHandler, FALSE);

    // Release any console handler waiting for the main thread to finish cleanup.
    // The event is intentionally left open until process exit: closing a HANDLE
    // while a console-handler thread may still be returning from a wait on it is
    // unsafe, and the OS will reclaim it when the process exits.
    if (signalmanager_gstate->shutdown_complete_event != NULL)
    {
        SetEvent((HANDLE) signalmanager_gstate->shutdown_complete_event);
    }

    while (atomicLoadExplicit(&windows_ctrl_handlers_active, memory_order_acquire) > 0)
    {
        wwSleepMS(1);
    }

    // Reset the first-stop-event flag now that no console handler is running.
    // Leaving it set would make a manager created later treat its very first
    // stop event as the second one and exit immediately.
    atomicStoreExplicit(&windows_stop_event_seen, false, memory_order_release);
#else
    // Blocks the handled signals and restores their default dispositions, so no
    // handler can observe the signal-safe state while it is being reset.
    restorePosixSignalHandlers();
    posix_shutdown_pipe_write_fd = -1;
    // Reset the first-signal flag too. Leaving it set would make a manager
    // created later treat its very first stop signal as the second one and exit
    // immediately instead of running the orderly shutdown.
    posix_stop_signal_seen = 0;

    // The read end is owned by worker 0's loop (added via wRead) and is closed
    // when that loop is destroyed, so only close the write end here.
    if (signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE] >= 0)
    {
        close(signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE]);
        signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE] = -1;
    }
#endif

    mutexDestroy(&(signalmanager_gstate->request_mutex));
    mutexDestroy(&(signalmanager_gstate->mutex));
    memoryFree(signalmanager_gstate);
    signalmanager_gstate = NULL;
}

/**
 * @brief Legacy termination entry, kept as a narrow compatibility layer.
 *
 * Contract:
 *   - on the main thread it performs orderly shutdown (registered callbacks,
 *     worker join, global-state teardown) exactly once;
 *   - off the main thread it remains a hard abort that SKIPS registered
 *     cleanup, because running teardown from an arbitrary worker/device/signal
 *     thread is the deadlock this design exists to prevent.
 *
 * Every off-main call site is therefore a call site that still has to be
 * audited and migrated to requestProgramShutdown() (orderly, returns to the
 * caller) or abortProgramNow() (deliberate hard abort).
 *
 * @param exit_code Process exit code, arbitrated through the exit-code policy.
 */
_Noreturn void terminateProgram(int exit_code)
{
    if (signalmanager_gstate == NULL)
    {
        // Signal manager not initialized yet (very early startup): just exit.
        // Avoids messy output when the program exits because, e.g., a file does
        // not exist.
        exit(exit_code);
    }

    signalmanagerSetExitCode(exit_code);

    if (exit_code == 0)
    {
        printError("SignalManager: Terminating program with exit-code 0 after successful completion\n");
    }
    else
    {
        printError("SignalManager: Terminating program with exit-code %d, please read above logs to understand why\n",
                   exit_code);
    }

    if (onMainThread())
    {
        // Already on the main worker thread: run the once-only shutdown
        // executor. It returns only when another worker-0 pass already owns the
        // sequence (for example a shutdown callback that called back into here),
        // in which case exiting directly is the correct non-recursive behavior.
        signalmanagerRunShutdownOnMainThread();
        exit(signalmanagerGetExitCode());
    }

    // Off the main thread this is still a hard abort. Calling
    // pthread_exit()/ExitThread() here can strand locks held by the fatal path
    // and deadlock worker-0 cleanup while it joins this thread, and running full
    // teardown off-main is the original signal bug in another shape.
    printError("SignalManager: terminateProgram(%d) called off the main thread (tid=%llu wid=%s); registered cleanup "
               "is SKIPPED. This call site must migrate to requestProgramShutdown() or abortProgramNow().\n",
               exit_code,
               (unsigned long long) getTID(),
               workerWIDLabel(getWID()));

#if defined(DEBUG)
    assert(! "terminateProgram() called off the main thread; use requestProgramShutdown()/abortProgramNow()");
#endif

    abortProgramNow(exit_code);
}

bool signalmanagerIsTerminating(void)
{
    return atomicLoadExplicit(&GSTATE.application_stopping_flag, memory_order_acquire);
}

bool isApplicationTerminating(void)
{
    return signalmanagerIsTerminating();
}
