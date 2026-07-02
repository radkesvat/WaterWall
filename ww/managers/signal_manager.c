/*
 * Signal handling runtime and process termination dispatch.
 *
 * The real shutdown work (running registered exit handlers, joining worker
 * threads and tearing down the global state) always runs on Waterwall's main
 * worker thread (worker 0). Signal handlers and the Windows console handler
 * only *request* shutdown; they never touch locks owned by the rest of the
 * program:
 *   - POSIX: the async signal handler writes the signal number to a self-pipe
 *     whose read end is watched at high priority by worker 0's event loop.
 *   - Windows: the console control handler posts a custom event to worker 0's
 *     loop and (for close/logoff/shutdown) waits on a bounded event while the
 *     main thread performs cleanup.
 * This removes the shutdown deadlocks that happened when cleanup ran directly
 * inside an async signal/console handler.
 */

#include "signal_manager.h"
#include "global_state.h"

#include <errno.h>

static signal_manager_t *signalmanager_gstate = NULL;

#define SHUTDOWN_PIPE_READ  0
#define SHUTDOWN_PIPE_WRITE 1

#if defined(OS_WIN)
enum
{
    // Bounded time a console close/logoff/shutdown handler waits for the main
    // thread to finish teardown before returning (and letting the OS kill us).
    kShutdownWaitTimeoutMs = 10000
};

static atomic_int windows_ctrl_handlers_active;
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
 * @brief Register one at-exit callback in reverse-priority slots.
 *
 * @param handle Callback function.
 * @param userdata Callback context.
 */
void registerAtExitCallBack(SignalHandler handle, void *userdata)
{
    assert(signalmanager_gstate != NULL);
    assert(signalmanager_gstate->handlers_len < kMaxSigHandles);
    mutexLock(&(signalmanager_gstate->mutex));
    for (int i = kMaxSigHandles - 1; i >= 0; i--)
    {
        if (signalmanager_gstate->handlers[i].handle == NULL)
        {
            signalmanager_gstate->handlers[i] = (signal_handler_t) {.handle = handle, .userdata = userdata};
            signalmanager_gstate->handlers_len++;
            mutexUnlock(&(signalmanager_gstate->mutex));

            return;
        }
    }
    mutexUnlock(&(signalmanager_gstate->mutex));

    printError("SignalManager: Too many atexit handlers, max is %d", kMaxSigHandles);
    _Exit(1);
}

/**
 * @brief Remove a previously registered at-exit callback.
 *
 * @param handle Callback function.
 * @param userdata Callback context.
 */
void removeAtExitCallBack(SignalHandler handle, void *userdata)
{
    assert(signalmanager_gstate != NULL);
    mutexLock(&(signalmanager_gstate->mutex));

    for (int i = 0; i < kMaxSigHandles; i++)
    {
        if (signalmanager_gstate->handlers[i].handle == handle &&
            signalmanager_gstate->handlers[i].userdata == userdata)
        {
            signalmanager_gstate->handlers[i] = (signal_handler_t) {.handle = NULL, .userdata = NULL};
            signalmanager_gstate->handlers_len--;
            mutexUnlock(&(signalmanager_gstate->mutex));

            return;
        }
    }
    // not found...
    mutexUnlock(&(signalmanager_gstate->mutex));
}

static void proceedWithNextExitHandler(void)
{
    for (unsigned int i = signalmanager_gstate->current_handler_index; i < kMaxSigHandles; i++)
    {
        if (signalmanager_gstate->handlers[i].handle != NULL)
        {
            signalmanager_gstate->current_handler_index = i + 1;
            signalmanager_gstate->handlers[i].handle(signalmanager_gstate->handlers[i].userdata, 0);
        }
    }
}

void signalmanagerSetExitCode(int exit_code)
{
    if (signalmanager_gstate == NULL)
    {
        return;
    }

    atomicStoreExplicit(&signalmanager_gstate->exit_code, exit_code, memory_order_release);
}

int signalmanagerGetExitCode(void)
{
    if (signalmanager_gstate == NULL)
    {
        return 0;
    }

    return (int) atomicLoadExplicit(&signalmanager_gstate->exit_code, memory_order_acquire);
}

/**
 * @brief Execute all registered shutdown callbacks once.
 *
 * Must run on worker 0 / the main thread. Sets application_stopping_flag the
 * first time it runs the real exit path; a second entry exits immediately.
 */
static void exitHandler(void)
{
    if (atomicLoadExplicit(&GSTATE.application_stopping_flag, memory_order_relaxed))
    {
        const char *msg     = "SignalManager: Finished\n";
        int         written = write(STDOUT_FILENO, msg, stringLength(msg));
        discard     written;
        _Exit(signalmanagerGetExitCode());
        return;
    }

    atomicStoreExplicit(&signalmanager_gstate->shutdown_requested, true, memory_order_release);

    int     written = write(STDOUT_FILENO, "SignalManager: Exiting... \n", 27);
    discard written;

    atomicStoreExplicit(&GSTATE.application_stopping_flag, true, memory_order_release);

    proceedWithNextExitHandler();
}

// --------------------------------------------------------------------------
// Main-thread shutdown handoff
// --------------------------------------------------------------------------

#if defined(OS_WIN)
/**
 * @brief Atomically mark that shutdown has been requested.
 *
 * @return Previous value: true means someone already requested shutdown and the
 *         caller should escalate to an immediate exit.
 */
static bool markShutdownRequested(void)
{
    return atomicExchangeExplicit(&signalmanager_gstate->shutdown_requested, true, memory_order_acq_rel);
}
#endif

static bool onMainThread(void)
{
    return (uint64_t) getTID() == GSTATE.main_thread_id;
}

/**
 * @brief Perform the real shutdown. Must be called on worker 0 / main thread.
 */
static void runMainThreadExit(void)
{
    exitHandler();
}

#if defined(OS_WIN)
static void worker0ShutdownEventCB(wevent_t *ev)
{
    discard ev;
    runMainThreadExit();
}
#else
static void worker0ShutdownPipeReadCB(wio_t *io, sbuf_t *buf)
{
    discard io;
    // Runs on worker 0 / main thread: reclaim the read buffer, then run the real
    // exit path (which tears down global state and exits the process).
    reuseBuffer(buf);
    runMainThreadExit();
}
#endif

#if defined(OS_WIN)
/**
 * @brief Wake worker 0 so it begins Windows console-requested shutdown.
 *
 * @return false when no handoff is possible.
 */
static bool wakeWorker0Shutdown(void)
{
    wloop_t *loop = getWorkerLoop(0);
    if (loop == NULL)
    {
        return false;
    }
    wevent_t ev;
    memoryZero(&ev, sizeof(ev));
    ev.loop = loop;
    ev.cb   = worker0ShutdownEventCB;
    weventSetPriority(&ev, WEVENT_HIGH_PRIORITY);
    return wloopPostEvent(loop, &ev);
}
#endif

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

    // A second console event after shutdown began forces an immediate exit.
    if (markShutdownRequested())
    {
        ExitProcess((UINT) signalmanagerGetExitCode());
    }

    signalmanagerSetExitCode(exit_code);

    if (! wakeWorker0Shutdown())
    {
        // Nothing to hand off to; exit now rather than run teardown here.
        ExitProcess((UINT) exit_code);
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
 * Only async-signal-safe operations are used: atomics and a single write() to
 * the self-pipe. The first signal records the exit code and wakes worker 0; a
 * second one forces an immediate exit so a stuck teardown cannot trap the user.
 */
static void posixGracefulSignalHandler(int signum)
{
    int saved_errno = errno;

    signal_manager_t *sm = signalmanager_gstate;
    if (sm == NULL)
    {
        // Manager already gone (very late during teardown): default + re-raise.
        signal(signum, SIG_DFL);
        raise(signum);
        errno = saved_errno;
        return;
    }

    if (atomicExchangeExplicit(&sm->shutdown_requested, true, memory_order_acq_rel))
    {
        _Exit(128 + signum);
    }

    atomicStoreExplicit(&sm->exit_code, 128 + signum, memory_order_release);

    unsigned char byte = (unsigned char) signum;
    ssize_t       w;
    do
    {
        w = write(sm->shutdown_pipe[SHUTDOWN_PIPE_WRITE], &byte, 1);
    } while (w < 0 && errno == EINTR);
    discard w;

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
    assert(io != NULL);
    weventSetPriority(io, WEVENT_HIGH_PRIORITY);

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

    *signalmanager_gstate = (signal_manager_t) {.handlers_len          = 0,
                                                .current_handler_index = 0,
                                                .exit_code             = 0,
                                                .started               = false,
                                                .raise_defaults        = true,
                                                .handle_sigint         = true,
                                                .handle_sigquit        = true,
                                                .handle_sighup  = false, // exits after ssh closed even with nohup
                                                .handle_sigill  = false,
                                                .handle_sigfpe  = true,
                                                .handle_sigabrt = false,
                                                .handle_sigsegv = false,
                                                .handle_sigterm = true,
                                                .handle_sigpipe = true,
                                                .handle_sigalrm = true};

#if defined(OS_WIN)
    signalmanager_gstate->shutdown_complete_event = NULL;
#else
    signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_READ]  = -1;
    signalmanager_gstate->shutdown_pipe[SHUTDOWN_PIPE_WRITE] = -1;
#endif

    mutexInit(&(signalmanager_gstate->mutex));
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
#else
    restorePosixSignalHandlers();

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

/**
 * @brief Terminate the process, running registered exit handlers on worker 0.
 *
 * @param exit_code Process exit code.
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
        // Already on the main worker thread: run the shutdown path directly.
        // termiateProgram is also called while processing exit handlers, so do
        // not restart them in that case to avoid an infinite loop.
        if (atomicLoadExplicit(&GSTATE.application_stopping_flag, memory_order_relaxed))
        {
            proceedWithNextExitHandler();
        }
        else
        {
            exitHandler();
        }
        // The shutdown path tears down global state and exits; this is a safety
        // net for the case where it returned without exiting.
        exit(exit_code);
    }

    // On another thread, fail fast. Calling pthread_exit()/ExitThread() here can
    // strand locks held by the fatal path and deadlock worker-0 cleanup while it
    // joins this thread. Running full teardown off-main is the original signal
    // bug in another shape, so immediate process exit is the least unsafe option.
    _Exit(exit_code);
}

bool signalmanagerIsTerminating(void)
{
    return atomicLoadExplicit(&GSTATE.application_stopping_flag, memory_order_acquire);
}

bool isApplicationTerminating(void)
{
    return signalmanagerIsTerminating();
}
