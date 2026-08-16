/*
 * Signal handling runtime and process shutdown dispatch.
 *
 * There are two shutdown entry points, with deliberately different
 * contracts:
 *
 *   requestProgramShutdown(code)  thread-safe orderly request. Records the exit
 *                                 status, wakes worker 0, and returns so the
 *                                 caller can unwind normally.
 *   abortProgramNow(code)         immediate _Exit() without registered cleanup,
 *                                 for corrupted state or failures reached while
 *                                 arbitrary locks may be held.
 * The main-thread shutdown controller owns worker, node, and global teardown.
 * SignalManager owns only OS delivery, worker-0 notification, fatal-signal
 * handling, and late non-owning observers:
 *   - POSIX: the async signal handler publishes a signal-safe mailbox and
 *     writes a best-effort wake edge to worker 0's self-pipe.
 *   - Windows: the console control handler and requestProgramShutdown() publish
 *     the same controller request and level-triggered worker-0 quiescence. A
 *     close/logoff/shutdown handler waits on a bounded completion event.
 * This removes the shutdown deadlocks that happened when cleanup ran directly
 * inside an async signal/console handler, without converting an off-main
 * orderly shutdown into an immediate _Exit() that skips cleanup.
 */

#include "signal_manager.h"
#include "application_shutdown.h"
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

static atomic_uint windows_ctrl_handler_gate;
// First console stop event flag; a second one forces an immediate exit.
static atomic_bool windows_stop_event_seen;

#define WINDOWS_HANDLER_GATE_CLOSED_SHIFT (sizeof(w_atomic_uint_value_t) * CHAR_BIT - 1U - W_ATOMIC_UINT_VALUE_SIGNED)
#define WINDOWS_HANDLER_GATE_CLOSED       ((w_atomic_uint_value_t) 1 << WINDOWS_HANDLER_GATE_CLOSED_SHIFT)
#define WINDOWS_HANDLER_GATE_COUNT_MASK   (WINDOWS_HANDLER_GATE_CLOSED - (w_atomic_uint_value_t) 1)

#ifdef SIGNAL_MANAGER_TEST_HOOKS
static void (*windows_before_entry_hook)(void *);
static void *windows_before_entry_context;
#endif
#else
/*
 * Minimal state the POSIX async handler is allowed to touch. It must not
 * dereference signalmanager_gstate, which can be freed during late teardown.
 * Both are reset while the handled signals are blocked in signalmanagerDestroy.
 */
static volatile sig_atomic_t posix_shutdown_pipe_write_fd = -1;
static volatile sig_atomic_t posix_stop_signal_seen       = 0;
static volatile sig_atomic_t posix_pending_signal         = 0;
#ifdef SIGNAL_MANAGER_TEST_HOOKS
static void (*posix_mailbox_hook)(void);
#endif

static void buildGracefulSignalSet(sigset_t *set);
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

#if defined(OS_WIN)
static bool windowsConsoleEventRecognized(DWORD ctrl_type)
{
    return ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT ||
           ctrl_type == CTRL_LOGOFF_EVENT || ctrl_type == CTRL_SHUTDOWN_EVENT;
}

static bool windowsHandlerGateEnter(void)
{
    w_atomic_uint_value_t state = atomicLoadExplicit(&windows_ctrl_handler_gate, memory_order_acquire);
    for (;;)
    {
        if ((state & WINDOWS_HANDLER_GATE_CLOSED) != 0 ||
            (state & WINDOWS_HANDLER_GATE_COUNT_MASK) == WINDOWS_HANDLER_GATE_COUNT_MASK)
        {
            return false;
        }
        if (atomicCompareExchangeExplicit(
                &windows_ctrl_handler_gate, &state, state + 1U, memory_order_acquire, memory_order_relaxed))
        {
            return true;
        }
    }
}

static void windowsHandlerGateLeave(void)
{
    const w_atomic_uint_value_t previous = atomicSubExplicit(&windows_ctrl_handler_gate, 1U, memory_order_release);
    assert((previous & WINDOWS_HANDLER_GATE_COUNT_MASK) != 0);
}

static void windowsHandlerGateCloseAndWait(void)
{
    discard atomic_fetch_or_explicit(&windows_ctrl_handler_gate, WINDOWS_HANDLER_GATE_CLOSED, memory_order_acq_rel);
    while ((atomicLoadExplicit(&windows_ctrl_handler_gate, memory_order_acquire) & WINDOWS_HANDLER_GATE_COUNT_MASK) !=
           0)
    {
        wwSleepMS(1);
    }
}
#endif

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
 * The registry mutex is never held while a callback runs. A callback may submit
 * a nonzero shutdown status through requestProgramShutdown(); it must not try to
 * continue the already-running sequence itself.
 */
void signalmanagerRunExitObservers(void)
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

#if ! defined(OS_WIN)
static bool signalmanagerBlockGracefulSet(sigset_t *previous)
{
    sigset_t graceful;
    buildGracefulSignalSet(&graceful);
    return pthread_sigmask(SIG_BLOCK, &graceful, previous) == 0;
}

static void signalmanagerRestoreSignalMask(const sigset_t *previous, int fallback_exit_code)
{
    const int restore_error = pthread_sigmask(SIG_SETMASK, previous, NULL);
    assert(restore_error == 0);
    if (restore_error != 0)
    {
        _Exit(fallback_exit_code != 0 ? fallback_exit_code : 1);
    }
}

static int signalmanagerTakePendingSignal(void)
{
    const int signum = (int) posix_pending_signal;

#ifdef SIGNAL_MANAGER_TEST_HOOKS
    if (posix_mailbox_hook != NULL)
    {
        posix_mailbox_hook();
    }
#endif
    posix_pending_signal = 0;
    return signum;
}

void signalmanagerConsumePendingShutdownSignal(void)
{
    sigset_t previous;
    if (! signalmanagerBlockGracefulSet(&previous))
    {
        return;
    }

    const int signum = signalmanagerTakePendingSignal();
    if (signum != 0)
    {
        discard applicationShutdownAcceptSignal(signum);
    }
    signalmanagerRestoreSignalMask(&previous, signum != 0 ? 128 + signum : 1);
}

application_shutdown_request_result_e signalmanagerArbitrateStartupFailure(int exit_code)
{
    if (signalmanager_gstate == NULL || ! signalmanager_gstate->started)
    {
        return applicationShutdownRequestTyped(exit_code, kApplicationShutdownReasonStartupFailure);
    }

    sigset_t previous;
    if (! signalmanagerBlockGracefulSet(&previous))
    {
        return applicationShutdownRequestTyped(exit_code, kApplicationShutdownReasonStartupFailure);
    }

    const int                             signum        = signalmanagerTakePendingSignal();
    application_shutdown_request_result_e signal_result = kApplicationShutdownRequestUnavailable;
    if (signum != 0)
    {
        signal_result = applicationShutdownAcceptSignal(signum);
    }
    const application_shutdown_request_result_e failure_result =
        applicationShutdownRequestTyped(exit_code, kApplicationShutdownReasonStartupFailure);

    signalmanagerRestoreSignalMask(&previous, signum != 0 ? 128 + signum : exit_code);
    return signal_result != kApplicationShutdownRequestUnavailable ? signal_result : failure_result;
}

#ifdef SIGNAL_MANAGER_TEST_HOOKS
void signalmanagerTestSetPosixMailboxHook(void (*hook)(void))
{
    posix_mailbox_hook = hook;
}
#endif

static void worker0ShutdownPipeReadCB(wio_t *io, sbuf_t *buf)
{
    discard io;
    signalmanagerConsumePendingShutdownSignal();
    reuseBuffer(buf);
}
#else
void signalmanagerConsumePendingShutdownSignal(void)
{
}

application_shutdown_request_result_e signalmanagerArbitrateStartupFailure(int exit_code)
{
    return applicationShutdownRequestTyped(exit_code, kApplicationShutdownReasonStartupFailure);
}
#endif

bool requestProgramShutdown(int exit_code)
{
    return applicationShutdownRequest(exit_code, kApplicationShutdownReasonProgrammatic);
}

bool signalmanagerRequestShutdownPreservingAcceptedStatus(int exit_code)
{
    return applicationShutdownRequestPreservingAcceptedStatus(exit_code, kApplicationShutdownReasonSubsystemFailure);
}

_Noreturn void abortProgramNow(int exit_code)
{
    applicationShutdownFatalStatusEscalate(exit_code);
    const int code = applicationShutdownFatalStatusSnapshot(exit_code);

#if defined(OS_WIN)
    ExitProcess((UINT) code);
#else
    _Exit(code);
#endif
}

/**
 * @brief Crash-signal handler: no Waterwall cleanup.
 *
 * Restores the default disposition and re-raises so the process still produces a
 * proper crash / core dump.
 */
static void fatalSignalHandler(int signum)
{
#if defined(OS_WIN)
    applicationShutdownFatalStatusEscalate(128 + signum);
    ExitProcess((UINT) applicationShutdownFatalStatusSnapshot(128 + signum));
#else
    struct sigaction action;
    memoryZero(&action, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    discard sigaction(signum, &action, NULL);

    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, signum);
    discard sigprocmask(SIG_UNBLOCK, &unblock, NULL);
    discard kill(getpid(), signum);
    _Exit(128 + signum);
#endif
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
#ifdef SIGNAL_MANAGER_TEST_HOOKS
    if (windows_before_entry_hook != NULL)
    {
        windows_before_entry_hook(windows_before_entry_context);
    }
#endif

    if (! windowsHandlerGateEnter())
    {
        if (! windowsConsoleEventRecognized(CtrlType))
        {
            return FALSE;
        }
        const int fallback = (CtrlType == CTRL_C_EVENT || CtrlType == CTRL_BREAK_EVENT) ? 130 : 0;
        ExitProcess((UINT) applicationShutdownFatalStatusSnapshot(fallback));
    }

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
        exit_code        = applicationShutdownFatalStatusSnapshot(0);
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
    if (atomicExchangeExplicit(&windows_stop_event_seen, true, memory_order_relaxed))
    {
        applicationShutdownFatalStatusEscalate(exit_code);
        ExitProcess((UINT) applicationShutdownFatalStatusSnapshot(exit_code));
    }

    // Same state machine and exit-code arbitration as POSIX: record the status,
    // hand the sequence to worker 0, never run cleanup here.
    if (applicationShutdownRequestTyped(exit_code, kApplicationShutdownReasonSignal) ==
        kApplicationShutdownRequestUnavailable)
    {
        // Nothing to hand off to; exit now rather than run teardown here.
        ExitProcess((UINT) applicationShutdownFatalStatusSnapshot(exit_code));
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
    windowsHandlerGateLeave();
    return handled;
}

#ifdef SIGNAL_MANAGER_TEST_HOOKS
bool signalmanagerTestDispatchWindowsConsoleEvent(unsigned long ctrl_type)
{
    return CtrlHandler((DWORD) ctrl_type) != FALSE;
}

void signalmanagerTestSetWindowsBeforeEntryHook(void (*hook)(void *), void *context)
{
    windows_before_entry_hook    = hook;
    windows_before_entry_context = context;
}
#endif

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
#if defined(OS_LINUX)
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0)
    {
        return 0;
    }
    if (errno != ENOSYS && errno != EINVAL)
    {
        return -1;
    }
#endif
    if (pipe(fds) != 0)
    {
        return -1;
    }
    for (int i = 0; i < 2; ++i)
    {
        int fl = fcntl(fds[i], F_GETFL, 0);
        if (fl == -1 || fcntl(fds[i], F_SETFL, fl | O_NONBLOCK) == -1)
        {
            goto fail;
        }
        int fd_fl = fcntl(fds[i], F_GETFD, 0);
        if (fd_fl == -1 || fcntl(fds[i], F_SETFD, fd_fl | FD_CLOEXEC) == -1)
        {
            goto fail;
        }
    }
    return 0;

fail:
    discard close(fds[0]);
    discard close(fds[1]);
    fds[0] = -1;
    fds[1] = -1;
    return -1;
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
    posix_pending_signal   = signum;

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

    unsigned char byte = (unsigned char) kShutdownRequestMarker;
    ssize_t       w;
    do
    {
        w = write(fd, &byte, 1);
    } while (w < 0 && errno == EINTR);

    if (w != 1 && ! (w < 0 && (errno == EAGAIN
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
                               || errno == EWOULDBLOCK
#endif
                               )))
    {
        // A failure other than an already-pending wake cannot make progress.
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

static bool installOneSigaction(int signum, void (*handler)(int), const sigset_t *mask)
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
        return false;
    }
    return true;
}

static bool installPosixSignalHandlers(void)
{
    signal_manager_t *sm = signalmanager_gstate;

    // While a graceful handler runs, block all graceful signals so its tiny body
    // is not re-entered.
    sigset_t graceful_mask;
    buildGracefulSignalSet(&graceful_mask);

    if (sm->handle_sigint)
    {
        if (! installOneSigaction(SIGINT, posixGracefulSignalHandler, &graceful_mask))
            return false;
    }
    if (sm->handle_sigterm)
    {
        if (! installOneSigaction(SIGTERM, posixGracefulSignalHandler, &graceful_mask))
            return false;
    }
    if (sm->handle_sigquit)
    {
        if (! installOneSigaction(SIGQUIT, posixGracefulSignalHandler, &graceful_mask))
            return false;
    }
    if (sm->handle_sighup)
    {
        if (! installOneSigaction(SIGHUP, posixGracefulSignalHandler, &graceful_mask))
            return false;
    }
    if (sm->handle_sigalrm)
    {
        if (! installOneSigaction(SIGALRM, posixGracefulSignalHandler, &graceful_mask))
            return false;
    }

    // Crash signals reset to default and re-raise; they never run cleanup.
    if (sm->handle_sigill)
    {
        if (! installOneSigaction(SIGILL, fatalSignalHandler, NULL))
            return false;
    }
    if (sm->handle_sigfpe)
    {
        if (! installOneSigaction(SIGFPE, fatalSignalHandler, NULL))
            return false;
    }
    if (sm->handle_sigabrt)
    {
        if (! installOneSigaction(SIGABRT, fatalSignalHandler, NULL))
            return false;
    }
    if (sm->handle_sigsegv)
    {
        if (! installOneSigaction(SIGSEGV, fatalSignalHandler, NULL))
            return false;
    }

    // Keep SIGPIPE ignored instead of routing it through shutdown.
    if (sm->handle_sigpipe)
    {
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        {
            return false;
        }
    }
    return true;
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
bool signalmanagerStart(void)
{
    assert(signalmanager_gstate != NULL);

    if (signalmanager_gstate->started)
    {
        printError("Error double signalmanagerStart()");
        return false;
    }

    signalmanager_gstate->started = true;

#if defined(OS_WIN)
    signalmanager_gstate->shutdown_complete_event = (void *) CreateEvent(NULL, TRUE, FALSE, NULL);
    if (signalmanager_gstate->shutdown_complete_event == NULL)
    {
        printError("Failed to create shutdown completion event!");
        signalmanager_gstate->started = false;
        return false;
    }

    if (! SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        printError("Failed to set console control handler!");
        CloseHandle((HANDLE) signalmanager_gstate->shutdown_complete_event);
        signalmanager_gstate->shutdown_complete_event = NULL;
        signalmanager_gstate->started                 = false;
        return false;
    }
    signalmanager_gstate->console_handler_registered = true;

    installWindowsFatalHandlers();
#else
    wloop_t *loop = getWorkerLoop(0);
    assert(loop != NULL);

    if (createShutdownPipe(signalmanager_gstate->shutdown_pipe) != 0)
    {
        printError("Failed to create shutdown self-pipe!");
        signalmanager_gstate->started = false;
        return false;
    }

    // Worker 0 watches the read end at high priority and runs the real shutdown.
    wio_t *io = wRead(loop, signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_READ], worker0ShutdownPipeReadCB);
    if (io == NULL)
    {
        printError("Failed to register shutdown self-pipe with worker 0 event loop\n");
        discard close(signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_READ]);
        discard close(signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE]);
        signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_READ]  = -1;
        signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE] = -1;
        signalmanager_gstate->started                            = false;
        return false;
    }
    assert(io != NULL);
    weventSetPriority(io, WEVENT_HIGH_PRIORITY);

    // Publish the write end into signal-safe storage before any handler that
    // uses it can run.
    posix_shutdown_pipe_write_fd = (sig_atomic_t) signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE];

    if (! installPosixSignalHandlers())
    {
        goto posix_start_failed;
    }

    // Handlers and the self-pipe are ready, so deliver graceful signals to the
    // main thread now (worker threads inherited the blocked mask that was set in
    // createGlobalState() before they were spawned).
    sigset_t graceful;
    buildGracefulSignalSet(&graceful);
    if (pthread_sigmask(SIG_UNBLOCK, &graceful, NULL) != 0)
    {
        goto posix_start_failed;
    }
#endif
    return true;

#if ! defined(OS_WIN)
posix_start_failed:
    restorePosixSignalHandlers();
    posix_shutdown_pipe_write_fd = -1;
    posix_stop_signal_seen       = 0;
    posix_pending_signal         = 0;
    wioClose(io);
    signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_READ] = -1;
    discard close(signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE]);
    signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE] = -1;
    signalmanager_gstate->started                            = false;
    return false;
#endif
}

signal_manager_t *signalmanagerCreate(void)
{
    assert(signalmanager_gstate == NULL);
    signal_manager_t *state = memoryAllocate(sizeof(*state));
    if (UNLIKELY(state == NULL))
    {
        return NULL;
    }

    *state = (signal_manager_t) {.handlers_len     = 0,
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
    state->shutdown_complete_event = NULL;
    atomicStoreExplicit(&windows_ctrl_handler_gate, 0, memory_order_release);
    atomicStoreExplicit(&windows_stop_event_seen, false, memory_order_relaxed);
#else
    state->shutdown_pipe[SHUTDOWN_PIPE_READ]  = -1;
    state->shutdown_pipe[SHUTDOWN_PIPE_WRITE] = -1;
#endif

    if (UNLIKELY(! mutexTryInit(&state->mutex)))
    {
        memoryFree(state);
        return NULL;
    }
    signalmanager_gstate = state;
    return state;
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
    if (signalmanager_gstate == NULL)
    {
        return;
    }

#if defined(OS_WIN)
    discard atomic_fetch_or_explicit(&windows_ctrl_handler_gate, WINDOWS_HANDLER_GATE_CLOSED, memory_order_acq_rel);

    if (signalmanager_gstate->console_handler_registered && ! SetConsoleCtrlHandler(CtrlHandler, FALSE))
    {
        if (signalmanager_gstate->shutdown_complete_event != NULL)
        {
            SetEvent((HANDLE) signalmanager_gstate->shutdown_complete_event);
        }
        abortProgramNow(applicationShutdownFatalStatusSnapshot(1));
    }
    signalmanager_gstate->console_handler_registered = false;

    // Release any console handler waiting for the main thread to finish cleanup.
    // The event is intentionally left open until process exit: closing a HANDLE
    // while a console-handler thread may still be returning from a wait on it is
    // unsafe, and the OS will reclaim it when the process exits.
    if (signalmanager_gstate->shutdown_complete_event != NULL)
    {
        SetEvent((HANDLE) signalmanager_gstate->shutdown_complete_event);
    }

    windowsHandlerGateCloseAndWait();

    // Reset the first-stop-event flag now that no console handler is running.
    // Leaving it set would make a manager created later treat its very first
    // stop event as the second one and exit immediately.
    atomicStoreExplicit(&windows_stop_event_seen, false, memory_order_relaxed);
#else
    // Blocks the handled signals and restores their default dispositions, so no
    // handler can observe the signal-safe state while it is being reset.
    restorePosixSignalHandlers();
    posix_shutdown_pipe_write_fd = -1;
    // Reset the first-signal flag too. Leaving it set would make a manager
    // created later treat its very first stop signal as the second one and exit
    // immediately instead of running the orderly shutdown.
    posix_stop_signal_seen = 0;
    posix_pending_signal   = 0;

    // The read end is owned by worker 0's loop (added via wRead) and is closed
    // when that loop is destroyed, so only close the write end here.
    if (signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE] >= 0)
    {
        close(signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE]);
        signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE] = -1;
    }
#endif

    mutexDestroy(&(signalmanager_gstate->mutex));
    memoryFree(signalmanager_gstate);
    signalmanager_gstate = NULL;
}
